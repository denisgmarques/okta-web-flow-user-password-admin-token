package br.com.icolabora.okta;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootApplication
@Slf4j
public class OktaTokenApplication implements ApplicationRunner {

	private RestTemplate restTemplate = new RestTemplate();
	private ObjectMapper mapper = new ObjectMapper();
	private String baseUrl = "https://dev-<FILL HERE>.okta.com";
	private String clientSecret = "<FILL HERE>";
	private String clientId = "<FILL HERE>";
	private String redirectUri = "<FILL HERE>";
	private String username = "<FILL HERE>";
	private String password = "<FILL HERE>";
	private SelfExpireToken token;
	private int tokenLifespanSeconds = 300; // Each 5 minutes will get a new token

	public static void main(String[] args) {
		SpringApplication.run(OktaTokenApplication.class, args);
	}

	@Override
	public void run(ApplicationArguments args) throws JsonProcessingException {

		/**
		 * E X A M P L E S
		 *
		 * Getting all users
		 */
		List<Map<String, String>> allUsers = findAllUsers();
		log.info("************ ALL USERS **************");
		log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(allUsers));

		/**
		 * Getting all groups
		 */
		List<Map<String, String>> allGroups = findAllGroups();
		log.info("************ ALL GROUPS **************");
		log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(allGroups));

		String firstUser = allUsers.get(0).get("id");
		String firstGroup = allGroups.get(0).get("id");

		/**
		 * Getting user by id and users for a group
		 */
		log.info("************ FIND GROUP BY ID **************");
		log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(findGroupById(firstGroup)));
		log.info("************ FIND USERS FOR A GROUP ID **************");
		log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(findUsersForGroup(firstGroup)));

		/**
		 * Getting user by id and groups for a user
		 */
		log.info("************ FIND USER BY ID **************");
		log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(findUserById(firstUser)));
		log.info("************ FIND GROUPS FOR A USER ID **************");
		log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(findGroupsForUser(firstUser)));
	}

	private HttpHeaders getApplicationJsonHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		return headers;
	}

	public HttpHeaders getApplicationJsonHeadersWithBearerToken() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.setBearerAuth(getAdminToken());
		return headers;
	}

	private HttpHeaders getWwwUrlEncodedBasicAuthHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setBasicAuth(Base64.getEncoder().withoutPadding().encodeToString((clientId + ":" + clientSecret).getBytes()));
		return headers;
	}

	/**
	 * Get an Okta Administration Token
	 */
	private String getAdminToken() {

		if (token != null && !token.isExpired()) return token.getValue();

		try {
			/**
			 * AUTHN REQUEST
			 */
			String uri = baseUrl + "/api/v1/authn";

			Map<String, String> map = new HashMap<>();
			map.put("username", username);
			map.put("password", password);

			HttpEntity<?> entity = new HttpEntity<Object>(mapper.writeValueAsString(map), getApplicationJsonHeaders());

			ParameterizedTypeReference<Map<String, Object>> typeRef = new ParameterizedTypeReference<>() {
			};

			ResponseEntity<Map<String, Object>> response = restTemplate.exchange(uri, HttpMethod.POST, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			String sessionToken = (String) response.getBody().get("sessionToken");
			log.info("sessionToken=" + sessionToken);

			log.info(uri);
			log.info(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			/**
			 * AUTHORIZE REQUEST
			 */
			uri = baseUrl + "/oauth2/v1/authorize";

			UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
					// Add query parameter
					.queryParam("client_id", clientId)
					.queryParam("redirect_uri", redirectUri)
					.queryParam("sessionToken", sessionToken);

			String fixedPart = "&scope=okta.users.read okta.groups.read&prompt=none&response_type=code&nonce=123&state=123";

			String getUri = builder.encode().build().toUri() + fixedPart;

			ResponseEntity<String> getResponse = restTemplate.getForEntity(getUri, String.class);

			if (!getResponse.getStatusCode().is3xxRedirection()) {
				throw new RuntimeException(getUri + " : " + getResponse.getStatusCode() + " - " + getResponse.getBody());
			}

			// Get the code value from redirected uri that will be something like:
			// 	http://localhost:8080/api/authorization-code/callback?code=gLCR_AQifZPK_DwvsSE8ByOmfF59PnGVSkHmK_N4zSA&state=123
			String responseUri = getResponse.getHeaders().get("Location").get(0);

			Pattern p = Pattern.compile("code=(?<code>[^&]+)");
			Matcher m = p.matcher(responseUri);
			String code = "";
			if (m.find()) {
				code = m.group("code");
				log.info("The code is: " + code);
			} else {
				throw new RuntimeException("The code was not found");
			}

			/**
			 * TOKEN REQUEST
			 */
			uri = baseUrl + "/oauth2/v1/token";

			MultiValueMap<String, String> mapEncoded = new LinkedMultiValueMap<>();
			mapEncoded.add("code", code);
			mapEncoded.add("grant_type", "authorization_code");
			mapEncoded.add("redirect_uri", redirectUri);

			HttpEntity formEntity = new HttpEntity<Object>(mapEncoded, getWwwUrlEncodedBasicAuthHeaders());

			response = restTemplate.exchange(uri, HttpMethod.POST, formEntity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			String tokenStr = (String) response.getBody().get("access_token");
			log.info("access_token=" + tokenStr);

			this.token = new SelfExpireToken(tokenStr, tokenLifespanSeconds);
			return token.getValue();
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting Okta Admin API Access Token");
		}
	}

	public List<Map<String, String>> findAllGroups() {
		try {
			/**
			 * GET GROUPS REQUEST
			 */
			String uri = baseUrl + "/api/v1/groups";

			HttpEntity entity = new HttpEntity(getApplicationJsonHeadersWithBearerToken());
			ParameterizedTypeReference<List<Map<String, Object>>> typeRef = new ParameterizedTypeReference<>() {};
			ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(uri, HttpMethod.GET, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			log.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			List<Map<String, String>> groupList = new ArrayList();
			for (Map<String, Object> group: response.getBody()) {
				Map<String, String> grFromBody = getGroupFromBody(group);
				if (!grFromBody.get("type").equals("BUILT_IN")) {
					groupList.add(grFromBody);
				}
			}

			return groupList;
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting all group");
		}
	}

	public List<Map<String, String>> findAllUsers() {
		try {
			/**
			 * GET USERS REQUEST
			 */
			String uri = baseUrl + "/api/v1/users";

			HttpEntity entity = new HttpEntity(getApplicationJsonHeadersWithBearerToken());
			ParameterizedTypeReference<List<Map<String, Object>>> typeRef = new ParameterizedTypeReference<>() {};
			ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(uri, HttpMethod.GET, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			log.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			List<Map<String, String>> userList = new ArrayList();
			for (Map<String, Object> user: response.getBody()) {
				userList.add(getUserFromBody(user));
			}

			return userList;
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting all users");
		}
	}

	public Map<String, String> findGroupById(final String id) {
		try {
			/**
			 * GET GROUP BY ID REQUEST
			 */
			String uri = baseUrl + "/api/v1/groups/" + id;

			HttpEntity entity = new HttpEntity(getApplicationJsonHeadersWithBearerToken());
			ParameterizedTypeReference<Map<String, Object>> typeRef = new ParameterizedTypeReference<>() {};
			ResponseEntity<Map<String, Object>> response = restTemplate.exchange(uri, HttpMethod.GET, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			log.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			return getGroupFromBody(response.getBody());
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting group by id");
		}
	}

	public Map<String, String> findUserById(final String id) {
		try {
			/**
			 * GET USER BY ID REQUEST
			 */
			String uri = baseUrl + "/api/v1/users/" + id;

			HttpEntity entity = new HttpEntity(getApplicationJsonHeadersWithBearerToken());
			ParameterizedTypeReference<Map<String, Object>> typeRef = new ParameterizedTypeReference<>() {};
			ResponseEntity<Map<String, Object>> response = restTemplate.exchange(uri, HttpMethod.GET, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			log.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			return getUserFromBody(response.getBody());
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting user by id");
		}
	}

	public List<Map<String, String>> findGroupsForUser(final String id) {
		try {
			/**
			 * GET GROUPS FOR USER REQUEST
			 */
			String uri = baseUrl + "/api/v1/users/" + id + "/groups";

			HttpEntity entity = new HttpEntity(getApplicationJsonHeadersWithBearerToken());
			ParameterizedTypeReference<List<Map<String, Object>>> typeRef = new ParameterizedTypeReference<>() {};
			ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(uri, HttpMethod.GET, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			log.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			List<Map<String, String>> groupList = new ArrayList();
			for (Map<String, Object> group: response.getBody()) {
				Map<String, String> grFromBody = getGroupFromBody(group);
				if (!grFromBody.get("type").equals("BUILT_IN")) {
					groupList.add(grFromBody);
				}
			}

			return groupList;
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting groups for user");
		}
	}

	public List<Map<String, String>> findUsersForGroup(final String id) {
		try {
			/**
			 * GET USERS FOR GROUP REQUEST
			 */
			String uri = baseUrl + "/api/v1/groups/" + id + "/users";

			HttpEntity entity = new HttpEntity(getApplicationJsonHeadersWithBearerToken());
			ParameterizedTypeReference<List<Map<String, Object>>> typeRef = new ParameterizedTypeReference<>() {};
			ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(uri, HttpMethod.GET, entity, typeRef);

			if (!response.getStatusCode().is2xxSuccessful()) {
				throw new RuntimeException(uri + " : " + response.getStatusCode() + " - " + response.getBody());
			}

			log.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()));

			List<Map<String, String>> userList = new ArrayList();
			for (Map<String, Object> user: response.getBody()) {
				userList.add(getUserFromBody(user));
			}

			return userList;
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Error getting users for group");
		}
	}

	private Map<String, String> getUserFromBody(Map<String, Object> body) {
		Map<String, String> userMap = new HashMap<>();

		Map<String, String> profile = (Map<String, String>) body.get("profile");
		userMap.put("id", (String) body.get("id"));
		userMap.put("firstName", profile.get("firstName"));
		userMap.put("lastName", profile.get("lastName"));
		userMap.put("email", profile.get("email"));

		return userMap;
	}

	private Map<String, String> getGroupFromBody(Map<String, Object> body) {
		Map<String, String> groupMap = new HashMap<>();

		Map<String, String> profile = (Map<String, String>) body.get("profile");
		groupMap.put("id", (String) body.get("id"));
		groupMap.put("name", ((Map<String, String>) body.get("profile")).get("name"));
		groupMap.put("type", (String) body.get("type"));

		return groupMap;
	}

}