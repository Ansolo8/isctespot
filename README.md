<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a id="readme-top"></a>
<br />
<div align="center">
  <img src="rgb_iscte_pt_horizontal_positive.png" alt="Logo" width="500" height="150">

  <h3 align="center">IscteSpot</h3>

  <p align="center">
    A Damn vulnerable SaaS application for ISCTE - Software and Application Security
    <br />
    <a href="https://github.com/othneildrew/Best-README-Template"><strong>Explore the docs »</strong></a>
    <br />
  </p>
</div>



<!-- ABOUT THE PROJECT -->
## About The Project

This project is targeted to the students of ISCTE that are enlisted in Software and Application Security course subject.
The students will use this project to understand the implications of security in modern web applications and understand the risks on the business level.

## Getting Started

There are 2 options to run the application, you can use Docker or you can install and run it locally. Below there will be 2 sections with installation steps for both cases.
First you can git clone this project to your desired location:
   ```sh
   git clone https://github.com/narfasec/isctespot.git
   ```

### Quick Start with Health Check Script

The easiest way to get started is using our automated health check and setup script:

```bash
cd isctespot/
python install.py
```

This script will:
- ✅ Check system requirements (Python 3.9, Node.js 18+, npm, MariaDB)
- ✅ Verify virtual environment and dependencies
- ✅ Test MariaDB connection on localhost:3306
- ✅ Offer to install missing packages
- ✅ Provide database setup options (clean, create, populate)
- ✅ Start all services in development mode
- ✅ Run health checks on all services

### Docker (Quick start)

[Install Docker](https://docs.docker.com/engine/install/), if not installed in your system.
* After installing docker, make sure docker deamon is running (opening the desktop app of Docker is enough)
* Change directory to iscte_spot and execute docker compose to build and start the project
  ```
  cd iscte_spot/
  docker-compose up --build
  ```
* Execute the setup script (**setup.ps1** for windows, **setup.sh** for Mac and Linux) to populate the database with testing data.
  ```
  .\setup.ps1
  ```
* At this stage your app should be ready. You can run health checks to check if everything is in order. You can go to you browser and paste **http://localhost:5173** and see the application interface.
  ```
  docker exec project-server-1 python /app/tests/health_checks/test_flow_1.py
  ```

## Local Setup (Manual Installation)

_Below are the steps to setup the project on your local environment. This is also the developer setup, with this setup you can easily make changes and debug issues._

### Prerequisites
* **Python 3.9+** - [Download from python.org](https://www.python.org/downloads/)
* **Node.js 18+** - [Download from nodejs.org](https://nodejs.org/)
* **MariaDB** - [Download from mariadb.com](https://mariadb.com/downloads/)
* **npm** - Usually comes with Node.js

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/narfasec/isctespot.git
   cd isctespot/
   ```

2. **Set up MariaDB**
   - Install MariaDB on your system
   - Start MariaDB service
   - Create database: `CREATE DATABASE iscte_spot;`
   - Set up user: `CREATE USER 'root'@'localhost' IDENTIFIED BY 'teste123';`
   - Grant privileges: `GRANT ALL PRIVILEGES ON iscte_spot.* TO 'root'@'localhost';`

3. **Set up Python environment**
   ```bash
   cd server/
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   # Linux/macOS
   source venv/bin/activate
   
   pip install -r requirements.txt
   ```

4. **Set up Frontend**
   ```bash
   cd frontend/admin-one-vue-tailwind-master/
   npm install
   ```

### Run Application

1. **Start MariaDB** (if not already running)

2. **Start Backend** (Terminal 1)
   ```bash
   cd server/
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   python appserver.py
   ```

3. **Start Frontend** (Terminal 2)
   ```bash
   cd frontend/admin-one-vue-tailwind-master/
   npm run dev
   ```

4. **Set up Database** (Terminal 3)
   ```bash
   cd server/db/setup/
   python clean_db.py
   python create_db.py
   python data_population.py
   ```

5. **Run Health Checks**
   ```bash
   cd server/
   python tests/health_checks/test_flow_1.py
   ```

### Service URLs
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000
- **Health Check**: http://localhost:5000/health
- **Admin Portal**: http://localhost:5000/ap/login
- **MariaDB**: localhost:3306
  
### Built With

* python
* Flask
* Vue
* Mariadb
  
## ⚠️ WARNING!
This is a vulnerable application, don't use it for real life scenario and specially don't expose it to the internet, it may compromise your systems
