[![Version](https://img.shields.io/hackage/v/yesod-auth-bcryptdb)](http://hackage.haskell.org/package/yesod-auth-bcryptdb)

# Yesod.Auth.BcryptDB

A **Yesod** authentication plugin designed to look users up in a **Persistent** database where the salted hash of their password is stored. This is based on **Yesod.Auth.HashDB** plugin, but it uses **BCrypt** to hash and salt the passwords.

To use this in a Yesod application, the foundation data type must be an instance of `YesodPersist`, and the username and hashed passwords should be added to the database. The following steps give an outline of what is required.

You need a database table to store user records: in a scaffolded site it might look like:

```haskell
User
    name Text             -- user name used to uniquely identify users
    password Text Maybe   -- password hash for BCryptDB
    UniqueUser name
```

Create an instance of `BCryptDBUser` for this data type:

```haskell
import Yesod.Auth.BcryptDB (BcryptDBUser(..))

instance BcryptDBUser User where
    userPasswordSaltedHash = userPassword
    setPasswordSaltedHash h u = u { userPassword = Just h }
```

In the `YesodAuth` instance declaration for your app, include `authBcryptDB` like so:

```haskell
import Yesod.Auth.BcryptDB (authBcryptDB)

instance YesodAuth App where
    authPlugins _ = [authBcryptDB (Just . UniqueUser), ....]
```

The argument to `authBcryptDB` is a function which takes a `Text` and produces a `Maybe` containing a **Unique** value to look up in the User table. The example `(Just . UniqueUser)` shown here works for the model outlined above.

For a real application, the developer should provide some sort of of administrative interface for setting passwords; it needs to call `setPassword` and save the result in the database. However, if you need to initialize the database by hand, you can generate the correct password hash as follows:

```haskell
$ ghci -XOverloadedStrings
> import Crypto.BCrypt
> hashPasswordUsingPolicy slowerBcryptHashingPolicy "mypassword"
```

## Custom Login Form

Instead of using the built-in HTML form, a custom one can be supplied by using `authBcryptDBWithForm` instead of `authBcryptDB`.

The custom form needs to be given as a function returning a `Widget`, since it has to build in the supplied "action" URL, and it must provide two text fields called "username" and "password". For example, the following modification of the outline code given above would replace the default form with a very minimal one which has no labels and a simple layout.

```haskell
instance YesodAuth App where
    authPlugins _ = [authBcryptDBWithForm myform (Just . UniqueUser), ....]

myform :: Route App -> Widget
myform action = $(whamletFile "templates/loginform.hamlet")
```

where *templates/loginform.hamlet* contains

```html
<form method="post" action="@{action}">
    <input name="username">
    <input type="password" name="password">
    <input type="submit" value="Login">
```

If a CSRF token needs to be embedded in a custom form, code must be included in the widget to add it - see `defaultForm` in the source code.

## JSON Interface

This plugin provides sufficient tools to build a complete JSON-based authentication flow. We assume that a design goal is to avoid URLs being built into the client, so all of the URLs needed are passed in JSON data.

To start the process, Yesod's defaultErrorHandler produces a JSON response if the HTTP Accept header gives \"application/json\" precedence over HTML. For a NotAuthenticated error, the status is 401 and the response contains the URL to use for authentication: this is the route which will be handled by the `loginHandler` method of the `YesodAuth` instance, which normally returns a login form.

Leaving the `loginHandler` aside for a moment, the final step - supported by this plugin since version 1.6 - is to POST the credentials for authentication in a JSON object. This object must include the properties "username" and "password". In the HTML case this would be the form submission, but here we want to use JSON instead.

In a JSON interface, the purpose of the `loginHandler` is to tell the client the URL for submitting the credentials. This requires a custom `loginHandler`, since the default one generates HTML only. It can find the correct URL by using the `submitRouteBcryptDB` function defined in this module.

Writing the `loginHandler` is made a little messy by the fact that its type allows only HTML content. A work-around is to send JSON as a short-circuit response, but we still make the choice using `selectRep` so as to get its matching of content types. Here is an example which is geared around using `BcryptDB` on its own, supporting both JSON and HTML clients:

```haskell
instance YesodAuth App where
   loginHandler = do
        submission <- submitRouteBcryptDB
        render <- lift getUrlRender
        typedContent@(TypedContent ct _) <- selectRep $ do
            provideRepType typeHtml $ return emptyContent
                           -- Dummy: the real Html version is at the end
            provideJson $ object [("loginUrl", toJSON $ render submission)]
        when (ct == typeJson) $
            sendResponse typedContent   -- Short-circuit JSON response
        defaultLoginHandler             -- Html response
```
