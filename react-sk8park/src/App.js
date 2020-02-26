import React from 'react';
import { Route, Switch } from 'react-router-dom'
import LoginForm from './LoginForm/LoginForm';
import Dashboard from './Dashboard/Dashboard';

export default class App extends React.Component{
    render() {
        return (
            <Switch>
                <Route exact path="/login" 
                    render={(props)=>{
                        if("access_token" in localStorage )
                            window.location.pathname = '/dashboard';
                        else
                            return <LoginForm/>;
                }} />
                <Route exact path="/dashboard" 
                    render={(props)=>{
                        if("access_token" in localStorage )
                            return <Dashboard/>;
                        else
                        window.location.pathname = '/login';
                }} />
            </Switch>
            )
        }
}