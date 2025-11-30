## 1. Requirements

Install the following:

### macOS
```
brew install docker openjdk@21 git
```

Start Docker Desktop.

### Linux (Ubuntu/Debian)
Add Docker's GPG key

```
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
|
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
```
Add Docker repository
```
echo
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg]
https://download.docker.com/linux/ubuntu
$(. /etc/os-release && echo $VERSION_CODENAME) stable"
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```
Install Docker + Compose plugin + Java + Git
```
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin openjdk-21-jdk git
```
Enable Docker:
```
sudo systemctl enable docker
sudo systemctl start docker
```

Verify installation:

```
java -version
docker --version
docker compose version
```

## 2. Clone the repository
```
git clone https://github.com/cekundu/securefilesICS0022.git
cd securefiles
```

## 3. Create your .env file

Create .env in the project root:

```
POSTGRES_USER=dbuser
POSTGRES_PASSWORD=CHANGE_ME
POSTGRES_DB=securefiles
DB_PORT=5433
```

Lock down permissions:

```
chmod 600 .env
```

Never commit this file.

## 4. Start PostgreSQL using Docker Compose

Start the DB:

```
docker compose up -d
```

Check running containers:
```
docker ps
```

Verify connection:
```
nc -z localhost 5433
```
## 5. Build the application JAR
```
chmod +x gradlew
./gradlew clean bootJar
```

The compiled CLI JAR will appear at:
```
build/libs/securefiles-0.0.1-SNAPSHOT.jar
```
## 6. Run the application using the launcher script

Make the script executable:
```
chmod +x securefiles.sh
```

Run:
```
./securefiles.sh
```

During first launch:

Liquibase creates the schema.

Liquibase inserts the bootstrap admin user. 
Credentials: 
```
username: admin
password: ChangeMe!123
```

The CLI menu becomes available.

Immediately change the admin password after first login.

## 7. Storage layout

Encrypted files are stored under:

```
data/<userId>/<uuid>.enc
```

Permissions:

Directories: 700

Files: 600

These permissions are applied automatically. Do not change them manually.

## 8. Running SecureFiles later

Simply run:

```
./securefiles.sh
```

PostgreSQL remains active in the background until you stop it:

```
docker compose down
```

To keep stored files, never use the -v flag unless you intend to wipe the database.

## 9. Resetting everything (clean wipe)

If you want to start fresh:
```
docker compose down -v
rm -rf data/
docker compose up -d
./gradlew clean bootJar
./securefiles.sh
```

This destroys all users and encrypted files.


## Troubleshooting


### "password authentication failed"


Fix .env, then:

```
docker compose down -v
docker compose up -d
```
### "port already in use"

Change DB_PORT in .env, then:

```
docker compose down
docker compose up -d
```

### "Permission denied" on writing to data/

Fix ownership and permissions:

```
sudo chown -R $USER:$USER data
chmod 700 data
```
