# Laravel JWT Auth Package
this package add a new driver for authorization api based on JWT 
### how can use it?
### after install this package:
``` 
    php artisan vendor:publish Zhitoo\Jwt\JWTServiceProvider
    php artisan jwt:secret
 ```
go to User model
```
use Zhitoo\Jwt\HasApiTokens;
.
.
.
use HasApiTokens
```

put auth:jwt to your route middleware like below
```
Route::middleware('auth:jwt')->get('/user', function (Request $request) {
    return $request->user();
});
```

login use createToken method fot create a new jwt token for current logedin user
```
Route::post('/login', function (Request $request) {
    $email = $request->input('email');
    $password = $request->input('password');
    if (\Illuminate\Support\Facades\Auth::attempt(['email' => $email, 'password' => $password])) {
        return response()->json(['ok' => true, 'token' => $request->user()->createToken()]);
    }
    abort(401);
});
```

logout use revokeAccessToken method
```
Route::middleware('auth:jwt')->post('/logout', function () {
    if (method_exists(auth()->user(), 'revokeAccessToken')) {
        auth()->user()->revokeAccessToken();
    }
    return response()->json(['ok' => true]);

});
```
### you can edit config in config/jwt.php file
### after install please go to config/jwt.php file and change secret key
