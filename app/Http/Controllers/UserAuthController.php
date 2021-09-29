<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;


    class UserAuthController extends Controller{
    /**
     * handle user registration request
     */
    public function registerUser(Request $request){
        
        $this->validate($request,[
            'name'=>'required',
            'email'=>'required|email|unique:users',
            'password'=>'required',
        ]);
        $user= User::create([
            'name' =>$request->name,
            'email'=>$request->email,
            'password'=>bcrypt($request->password)
        ]);

        $token = $user->createToken('medical')->accessToken;
 
        return response()->json(
            [
                'status'=>"success",
                'data'=>$user,
                'token' => $token
            ]
            , 200);
    }

    /**
     * login user to our application
     */
    public function loginUser(Request $request){
        $login_credentials=[
            'email'=>$request->email,
            'password'=>$request->password,
        ];
        if(auth()->attempt($login_credentials)){
            //generate the token for the user
            $user_login_token= auth()->user()->createToken('medical')->accessToken;
            //now return this token on success login attempt
            return response()->json(
                [
                    'status'=>"success",
                    'data'=>$login_credentials,
                    'token' => $user_login_token
                ]
                , 200);
        }
        else{
            //wrong login credentials, return, user not authorised to our system, return error code 401
            return response()->json(['error' => 'UnAuthorised Access'], 401);
        }
    }

    /**
     * This method returns authenticated user details
     */
    public function UserDetails(){
        //returns details
        return response()->json(['authenticated-user' => auth()->user()], 200);
    }
}
