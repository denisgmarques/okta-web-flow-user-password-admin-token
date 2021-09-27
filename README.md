# okta-web-flow-user-password-admin-token
This project shows how to get an Okta API administrator Token to list users and groups using the administrator login and password instead of an API token

# Pre-requisites
- Java
- Maven

# Setup Okta account

- Create an okta developer account
- Create an user and a group at least
- Configure on Okta API / Administrators an user to be a read only administrator
- Create an application of type web and grant de scopes: okta.users.read / okta.groups.read 

# Configuring parameters

- Open the OktaTokenApplication class and fill this parameters
```
	private String baseUrl = "https://dev-<FILL HERE>.okta.com";
	private String clientSecret = "<FILL HERE>";
	private String clientId = "<FILL HERE>";
	private String redirectUri = "<FILL HERE>";
	private String username = "<FILL HERE>";
	private String password = "<FILL HERE>";

```

# Running the project

- In the root folder type 
```
mvn spring-boot:run
```
