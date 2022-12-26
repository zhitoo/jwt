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
use Hshafiei374\Jwt\HasApiTokens;
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
### you can edit config in config/jwt.php file
### after install please go to config/jwt.php file and change secret key
