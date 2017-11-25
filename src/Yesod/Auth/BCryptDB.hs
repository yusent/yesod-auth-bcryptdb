{-# LANGUAGE ConstraintKinds   #-}
{-# LANGUAGE CPP               #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TypeFamilies      #-}

module Yesod.Auth.BCryptDB
  ( BCryptDBUser(..)
  , Password
  , setPassword
  , validateCreds
  -- * Interface to database and Yesod.Auth
  , authBCryptDB
  , authBCryptDBWithForm
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

type Password = Text

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
  userPasswordSaltedHash :: user -> Text

  {-# MINIMAL setPasswordSaltedHash, userPasswordSaltedHash #-}

-- | Calculate salted hash using Bcrypt.
saltAndHashPassword :: Password -> HashingPolicy -> IO (Maybe Text)
saltAndHashPassword password hashingPolicy = do
   hash <- hashPasswordUsingPolicy hashingPolicy . BS.pack $ unpack password
   return $ pack . BS.unpack <$> hash

-- | Set password for user. This function should be used for setting
--   passwords. It generates random salt and calculates proper hashes.
setPassword :: BCryptDBUser user => Password -> HashingPolicy -> user -> IO user
setPassword password hashingPolicy user = do
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
  -> Password
  -> HandlerT master IO Bool
validateCreds userID password = do
  -- Checks that hash and password match
  mUser <- runDB $ getBy userID

  return $ case mUser of
                Nothing -> False

                Just (Entity _ user) ->
                  validatePassword
                    (BS.pack . unpack $ userPasswordSaltedHash user)
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
  => (Text -> Unique user)
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
                  $ validateCreds <$> fmap uniq mUser <*> mPass

  if isValid
      then lift . setCredsRedirect $ Creds "bcryptdb" (fromMaybe "" mUser) []
      else loginErrorMessageI LoginR InvalidUsernamePass

-- | Prompt for username and password, validate that against a database
--   which holds the username and a salted hash of the password
authBCryptDB
  :: BCryptDBPersist master user
  => (Text -> Unique user)
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
  -> (Text -> Unique user)
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
