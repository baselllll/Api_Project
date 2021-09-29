<?php

namespace App\Http\Controllers;

use App\Models\Admin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AdminAuthController extends Controller{
    /**
     * handle user registration request
     */
    public function registerUser(Request $request){
        
        $this->validate($request,[
            'name'=>'required',
            'email'=>'required|email|unique:users',
            'password'=>'required',
        ]);
        $user= Admin::create([
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

        $admin = Admin::all();
        foreach($admin as $row){
            if($row->email==$login_credentials['email'] && Hash::check($login_credentials['password'], $row->password)){
                $user_login_token=  $row->createToken('medical')->accessToken;
                return response()->json(
                    [
                        'status'=>"success",
                        'data'=>$login_credentials,
                        'token' => $user_login_token
                    ]
                    , 200);
            }
        }
        return response()->json(['error' => 'UnAuthorised Access'], 401);
    }

    /**
     * This method returns authenticated user details
     */
    public function UserDetails(){
        $admin = Admin::all();
        return response()->json(['authenticated-admin' => $admin], 200);
    }
}
