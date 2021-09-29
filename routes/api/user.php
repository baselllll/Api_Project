<?php

use App\Http\Controllers\UserAuthController;
use Illuminate\Support\Facades\Route;


Route::post('register',[UserAuthController::class,'registerUser']);
Route::post('login',[UserAuthController::class,'loginUser']);
//add this middleware to ensure that every request is authenticated
Route::middleware('auth:api')->group(function(){
    Route::get('getalluser', [UserAuthController::class,'UserDetails']);
});
