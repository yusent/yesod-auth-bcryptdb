{-# LANGUAGE ConstraintKinds   #-}
{-# LANGUAGE CPP               #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TypeFamilies      #-}
-------------------------------------------------------------------------------
-- |
-- Module      :  Yesod.Auth.BCryptDB
-- Copyright   :  (c) Yusent Chig 2017
-- License     :  MIT
--
-- Maintainer  :  Yusent Chig <yusent@protonmail.com>
-- Stability   :  Stable
-- Portability :  Portable
--
-- A Yesod authentication plugin designed to look users up in a Persistent
-- database where the salted hash of their password is stored. This is based
-- on Yesod.Auth.HashDB plugin, but it uses BCrypt to hash and salt the
-- passwords.
--
-- To use this in a Yesod application, the foundation data type must be an
-- instance of YesodPersist, and the username and hashed passwords should
-- be added to the database.  The following steps give an outline of what
-- is required.
--
-- You need a database table to store user records: in a scaffolded site it
-- might look like:
--
-- > User
-- >     name Text             -- user name used to uniquely identify users
-- >     password Text Maybe   -- password hash for BCryptDB
-- >     UniqueUser name
--
-- Create an instance of 'BCryptDBUser' for this data type:
--
-- > import Yesod.Auth.BcryptDB (BcryptDBUser(..))
-- > ....
-- > instance BcryptDBUser User where
-- >     userPasswordSaltedHash = userPassword
-- >     setPasswordSaltedHash h u = u { userPassword = Just h }
--
-- In the YesodAuth instance declaration for your app, include 'authBcryptDB'
-- like so:
--
-- > import Yesod.Auth.BcryptDB (authBcryptDB)
-- > ....
-- > instance YesodAuth App where
-- >     ....
-- >     authPlugins _ = [authBcryptDB (Just . UniqueUser), ....]
--
-- The argument to 'authBcryptDB' is a function which takes a 'Text' and
-- produces a 'Maybe' containing a 'Unique' value to look up in the User
-- table. The example @(Just . UniqueUser)@ shown here works for the model
-- outlined above.
--
-- For a real application, the developer should provide some sort of
-- of administrative interface for setting passwords; it needs to call
-- 'setPassword' and save the result in the database.  However, if you
-- need to initialise the database by hand, you can generate the correct
-- password hash as follows:
--
-- > ghci -XOverloadedStrings
-- > > import Crypto.BCrypt
-- > > hashPasswordUsingPolicy slowerBcryptHashingPolicy "mypassword"
--
-- == Custom Login Form
--
-- Instead of using the built-in HTML form, a custom one can be supplied
-- by using 'authBcryptDBWithForm' instead of 'authBcryptDB'.
--
-- The custom form needs to be given as a function returning a Widget, since
-- it has to build in the supplied "action" URL, and it must provide two text
-- fields called "username" and "password".  For example, the following
-- modification of the outline code given above would replace the default
-- form with a very minimal one which has no labels and a simple layout.
--
-- > instance YesodAuth App where
-- >     ....
-- >     authPlugins _ = [authBcryptDBWithForm myform (Just . UniqueUser), ....]
-- >
-- > myform :: Route App -> Widget
-- > myform action = $(whamletFile "templates/loginform.hamlet")
--
-- where templates/loginform.hamlet contains
--
-- > <form method="post" action="@{action}">
-- >     <input name="username">
-- >     <input type="password" name="password">
-- >     <input type="submit" value="Login">
--
-- If a CSRF token needs to be embedded in a custom form, code must be
-- included in the widget to add it - see @defaultForm@ in the source
-- code of this module for an example.
--
-- == JSON Interface
--
-- This plugin provides sufficient tools to build a complete JSON-based
-- authentication flow.  We assume that a design goal is to avoid URLs
-- being built into the client, so all of the URLs needed are passed in
-- JSON data.
--
-- To start the process, Yesod's defaultErrorHandler produces a JSON
-- response if the HTTP Accept header gives \"application/json\"
-- precedence over HTML.  For a NotAuthenticated error, the status is
-- 401 and the response contains the URL to use for authentication: this
-- is the route which will be handled by the loginHandler method of the
-- YesodAuth instance, which normally returns a login form.
--
-- Leaving the loginHandler aside for a moment, the final step - supported
-- by this plugin since version 1.6 - is to POST the credentials for
-- authentication in a JSON object.  This object must include the
-- properties "username" and "password".  In the HTML case this would be
-- the form submission, but here we want to use JSON instead.
--
-- In a JSON interface, the purpose of the loginHandler is to tell the
-- client the URL for submitting the credentials.  This requires a
-- custom loginHandler, since the default one generates HTML only.
-- It can find the correct URL by using the 'submitRouteBcryptDB'
-- function defined in this module.
--
-- Writing the loginHandler is made a little messy by the fact that its
-- type allows only HTML content.  A work-around is to send JSON as a
-- short-circuit response, but we still make the choice using selectRep
-- so as to get its matching of content types.  Here is an example which
-- is geared around using BcryptDB on its own, supporting both JSON and HTML
-- clients:
--
-- > instance YesodAuth App where
-- >    ....
-- >    loginHandler = do
-- >         submission <- submitRouteBcryptDB
-- >         render <- lift getUrlRender
-- >         typedContent@(TypedContent ct _) <- selectRep $ do
-- >             provideRepType typeHtml $ return emptyContent
-- >                            -- Dummy: the real Html version is at the end
-- >             provideJson $ object [("loginUrl", toJSON $ render submission)]
-- >         when (ct == typeJson) $
-- >             sendResponse typedContent   -- Short-circuit JSON response
-- >         defaultLoginHandler             -- Html response
--
-------------------------------------------------------------------------------
module Yesod.Auth.BCryptDB
  ( BCryptDBUser(..)
  , setPassword
  , setPasswordWithHashingPolicy
  -- * Interface to database and Yesod.Auth
  , authBCryptDB
  , authBCryptDBWithForm
  , submitRouteBcryptDB
  , validateCreds
  ) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative                   ((<$>), (<*>), pure)
#endif
import Crypto.BCrypt
import Data.Aeson                            ((.:?))
import qualified Data.ByteString.Char8 as BS (pack, unpack)
import Data.Text                             (Text, pack, unpack)
import Data.Maybe                            (fromMaybe)
import Yesod.Auth
import Yesod.Core
import Yesod.Form
import Yesod.Persist
import Yesod.Auth.Message                    (AuthMessage(InvalidUsernamePass))

#if !MIN_VERSION_yesod_core(1,4,14)
defaultCsrfParamName :: Text
defaultCsrfParamName = "_token"
#endif

-- | The type representing user information stored in the database should
--   be an instance of this class.  It just provides the getter and setter
--   used by the functions in this module.
class BCryptDBUser user where
  -- | Setter used by 'setPassword' and 'upgradePasswordHash'.  Produces a
  --   version of the user data with the hash set to the new value.
  --
  setPasswordSaltedHash
    :: Text -- ^ Password hash
    -> user
    -> user

  -- | Getter used by 'validatePass' and 'upgradePasswordHash' to
  --   retrieve the password hash from user data
  --
  userPasswordSaltedHash :: user -> Maybe Text

  {-# MINIMAL setPasswordSaltedHash, userPasswordSaltedHash #-}

-- | Calculate salted hash using Bcrypt.
saltAndHashPassword :: Text -> HashingPolicy -> IO (Maybe Text)
saltAndHashPassword password hashingPolicy = do
   hash <- hashPasswordUsingPolicy hashingPolicy . BS.pack $ unpack password
   return $ pack . BS.unpack <$> hash

-- | Set password for user. This function should be used for setting
--   passwords. It generates random salt and calculates proper hashes.
setPassword
  :: BCryptDBUser user
  => Text          -- ^ Password
  -> user
  -> IO user
setPassword = setPasswordWithHashingPolicy slowerBcryptHashingPolicy

-- | Set password for user. This function should be used for setting passwords
-- with an specified hashing policy. It generates random salt and calculates
-- proper hashes.
setPasswordWithHashingPolicy
  :: BCryptDBUser user
  => HashingPolicy
  -> Text          -- ^ Password
  -> user
  -> IO user
setPasswordWithHashingPolicy hashingPolicy password user = do
    mHash <- saltAndHashPassword password hashingPolicy
    return $ case mHash of
                  Nothing   -> user
                  Just hash -> setPasswordSaltedHash hash user

----------------------------------------------------------------
-- Authentication
----------------------------------------------------------------

-- | Given a user ID and password in plain text, validate them against
--   the database values.
validateCreds
  :: BCryptDBPersist master user
  => Unique user                 -- ^ User unique identifier
  -> Text                        -- ^ Password given
  -> HandlerT master IO Bool
validateCreds userID password = do
  -- Checks that hash and password match
  mUser <- runDB $ getBy userID

  return $ case userPasswordSaltedHash . entityVal =<< mUser of
                Nothing -> False

                Just storedPassword ->
                  validatePassword
                    (BS.pack $ unpack storedPassword)
                    (BS.pack $ unpack password)

----------------------------------------------------------------
-- Interface to database and Yesod.Auth
----------------------------------------------------------------

-- | Constraint for types of interface functions in this module
--
type BCryptDBPersist master user =
  ( YesodAuthPersist master
  , PersistUnique (YesodPersistBackend master)
  , AuthEntity master ~ user
#if MIN_VERSION_persistent(2,5,0)
  , PersistEntityBackend user ~ BaseBackend (YesodPersistBackend master)
#else
  , PersistEntityBackend user ~ YesodPersistBackend master
#endif
  , BCryptDBUser user
  , PersistEntity user
  )

-- Internal data type for receiving JSON encoded username and password
data UserPass = UserPass (Maybe Text) (Maybe Text)

instance FromJSON UserPass where
  parseJSON (Object v) = UserPass <$> v .:? "username" <*> v .:? "password"
  parseJSON _          = pure $ UserPass Nothing Nothing

login :: AuthRoute
login = PluginR "bcryptdb" ["login"]

-- | Handle the login form. First parameter is function which maps
--   username (whatever it might be) to unique user ID.
postLoginR
  :: BCryptDBPersist master user
  => (Text -> Maybe (Unique user))
  -> HandlerT Auth (HandlerT master IO) TypedContent
postLoginR uniq = do
  jsonContent <- fmap ((== "application/json") . simpleContentType)
             <$> lookupHeader "Content-Type"

  UserPass mUser mPass <-
      case jsonContent of
           Just True -> requireJsonBody
           _         -> lift . runInputPost $ UserPass
                          <$> iopt textField "username"
                          <*> iopt textField "password"

  isValid <- lift . fromMaybe (return False)
                  $ validateCreds <$> (uniq =<< mUser) <*> mPass

  if isValid
      then lift . setCredsRedirect $ Creds "bcryptdb" (fromMaybe "" mUser) []
      else loginErrorMessageI LoginR InvalidUsernamePass

-- | Prompt for username and password, validate that against a database
--   which holds the username and a salted hash of the password
authBCryptDB
  :: BCryptDBPersist master user
  => (Text -> Maybe (Unique user))
  -> AuthPlugin master
authBCryptDB = authBCryptDBWithForm defaultForm

-- | Like 'authBCryptDB', but with an extra parameter to supply a custom HTML
-- form.
--
-- The custom form should be specified as a function which takes a route to
-- use as the form action, and returns a Widget containing the form.  The
-- form must use the supplied route as its action URL, and, when submitted,
-- it must send two text fields called "username" and "password".
--
-- Please see the example in the documentation at the head of this module.
--
authBCryptDBWithForm
  :: BCryptDBPersist master user
  => (Route master -> WidgetT master IO ())
  -> (Text -> Maybe (Unique user))
  -> AuthPlugin master
authBCryptDBWithForm form uniq =
  AuthPlugin "bcryptdb" dispatch $ \tm -> form (tm login)
  where
    dispatch "POST" ["login"] = postLoginR uniq >>= sendResponse
    dispatch _ _              = notFound

defaultForm :: Yesod app => Route app -> WidgetT app IO ()
defaultForm loginRoute = do
  request <- getRequest
  let mtok = reqToken request
  toWidget [hamlet|
    $newline never
    <div id="header">
      <h1>Login

    <div id="login">
      <form method="post" action="@{loginRoute}">
        $maybe tok <- mtok
          <input type=hidden name=#{defaultCsrfParamName} value=#{tok}>
        <table>
          <tr>
            <th>Username:
            <td>
              <input id="x" name="username" autofocus="" required>
          <tr>
            <th>Password:
            <td>
              <input type="password" name="password" required>
          <tr>
            <td>&nbsp;
            <td>
              <input type="submit" value="Login">

        <script>
          if (!("autofocus" in document.createElement("input"))) {
            document.getElementById("x").focus();
          }
  |]

-- | The route, in the parent site, to which the username and password
--   should be sent in order to log in.  This function is particularly
--   useful in constructing a 'loginHandler' function which provides a
--   JSON response.  See the \"JSON Interface\" section above for more
--   details.
--
submitRouteBcryptDB
  :: YesodAuth site
  => HandlerT Auth (HandlerT site IO) (Route site)
submitRouteBcryptDB = do
    toParent <- getRouteToParent
    return $ toParent login
