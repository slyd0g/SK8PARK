import React from 'react';
import { stack as Menu } from 'react-burger-menu';
import './sidebar.css'

export default class Dashboard extends React.Component {
  constructor(props){
    super(props);
    this.state = {
      version: [],
      users: [],
    }
  }

  componentDidMount() {
    this.refreshAccess()
    setInterval(this.refreshAccess, 60000);
  }

  async refreshAccess() {
      await fetch('http://localhost:5000/api/admin/token/refresh', 
        {
          method: 'POST',
          headers: {
            'CustomAuthorization': 'Bearer ' + localStorage.getItem('refresh_token')
          }
        })
        .then((response) => response.json())
        .then((responseJson) => {
          if(responseJson.hasOwnProperty('access_token'))
          {
            localStorage.setItem('access_token', responseJson.access_token)
          }
          else
          {
            localStorage.clear()
            window.location.pathname = '/login';
          }
        })    
  }
  

  handleGetClick = (api_endpoint, state_update) => {
    fetch(api_endpoint, {
              method: 'GET',
              headers: {
                'CustomAuthorization': 'Bearer ' + localStorage.getItem('access_token')
              }
            })
            .then(res => res.json())
            .then((data) => {
              this.setState({ [state_update]: data},function () {
                console.log(this.state[state_update]);
            });
              
            })
            .catch(console.log)
  }

  handleLogoutClick = () => {
    fetch('http://localhost:5000/api/admin/logout/access', {
      method: 'POST',
      headers: {
        'CustomAuthorization': 'Bearer ' + localStorage.getItem('access_token')
      }
    })
    fetch('http://localhost:5000/api/admin/logout/refresh', {
      method: 'POST',
      headers: {
        'CustomAuthorization': 'Bearer ' + localStorage.getItem('refresh_token')
      }
    })
    localStorage.clear()
    window.location.pathname = '/login';
  }

  render() {
    return (
    

    <div>
      <div id="page-wrap">
        <h1>SK8PARK Dashboard</h1>
      </div>

      <Menu>
        
        <a className="menu-item" href="/dashboard">
          Home
        </a>

        <button className='astext' onClick={() => this.handleGetClick('http://localhost:5000/api/version', 'version')}>
          Version
        </button>
        
        <button className='astext' onClick={() => this.handleGetClick('http://localhost:5000/api/admin/users', 'users')}>
          Users
        </button>
        
        <button className='astext' onClick={() => this.handleGetClick('http://localhost:5000/api/SK8RATs', 'sk8rats')}>
          SK8RATs
        </button>

        <button className='astext' onClick={() => this.handleLogoutClick()}>
          Logout
        </button>

      </Menu>
                  
      <h2>hello</h2>
      hello
      
    </div>  
    );
  }
}



//<pre>{JSON.stringify(this.state.version, null, 2) }</pre>
//<pre>{JSON.stringify(this.state.users, null, 2) }</pre>