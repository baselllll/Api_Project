<?php

use App\Http\Controllers\AdminAuthController;
use Illuminate\Support\Facades\Route;


Route::post('register',[AdminAuthController::class,'registerUser']);
Route::post('login',[AdminAuthController::class,'loginUser']);
Route::middleware('auth:adminapi')->group(function(){
    Route::get('getalladmin', [AdminAuthController::class,'UserDetails']);
});
