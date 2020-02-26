import React, { Component } from 'react';
import './LoginForm.css';

export default class LoginForm extends Component {
    constructor(){
        super();
        this.handleChange = this.handleChange.bind(this);
    }

    handleSubmit(event) {
        event.preventDefault();
        const data = new FormData(event.target);
        
        fetch('http://localhost:5000/api/admin/login', {
          method: 'POST',
          body: data,
        })
        .then((response) => response.json())
        .then((responseJson) => {
          if(responseJson.hasOwnProperty('access_token'))
          {
            console.log(responseJson.access_token)
            localStorage.setItem('access_token', responseJson.access_token)
            localStorage.setItem('refresh_token', responseJson.refresh_token)
            window.location.pathname = '/dashboard';
          }
          else
          {
            window.location.pathname = '/login';
          }
          
        })
      }

    render() {
        return (
            <div className="center">
                <div className="card">
                <img src="/images/sk8rat.jpg" alt="Skate rat" height="200" width="200" className="centerimage"></img>
                    <h1>SK8PARK Login</h1>
                    <form onSubmit={this.handleSubmit}>
                        <input
                            className="form-item"
                            placeholder="Username"
                            name="username"
                            type="text"
                            onChange={this.handleChange}
                        />
                        <input
                            className="form-item"
                            placeholder="Password"
                            name="password"
                            type="password"
                            onChange={this.handleChange}
                        />
                        <input
                            className="form-submit"
                            value="SUBMIT"
                            type="submit"
                        />
                    </form>
                </div>
            </div>
        );
    }

    handleChange(e){
        this.setState(
            {
                [e.target.name]: e.target.value
            }
        )
    }
}