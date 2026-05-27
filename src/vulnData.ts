/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { VulnerabilityDef } from "./types.ts";

export const VULNERABILITY_DATABASE: VulnerabilityDef[] = [
  {
    cweId: "CWE-89",
    name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    description: "The application constructs an SQL command using raw user input without proper validation or parameterization, allowing an attacker to manipulate the query database commands.",
    severity: "CRITICAL",
    category: "Injection",
    commonCVEs: ["CVE-2022-42889", "CVE-2023-38646", "CVE-2021-36749"],
    vulnerableExample: `// Spring Boot Java - Vulnerable SQL Construction
@GetMapping("/user")
public User getUser(@RequestParam String id) {
    String query = "SELECT * FROM users WHERE id = '" + id + "'";
    return jdbcTemplate.queryForObject(query, new UserRowMapper());
}`,
    secureExample: `// Spring Boot Java - Secure Parameterized Query
@GetMapping("/user")
public User getUser(@RequestParam String id) {
    String query = "SELECT * FROM users WHERE id = ?";
    return jdbcTemplate.queryForObject(query, new Object[]{id}, new UserRowMapper());
}`,
    remediationExplanation: "Always use Parameterized Queries (PreparedStatement in Java or parameterized placeholders in any framework) rather than raw string concatenation. Alternatively, leverage ORM technologies like Hibernate/JPA which use parametrized mappings by default."
  },
  {
    cweId: "CWE-79",
    name: "Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')",
    description: "Unsanitized user-supplied input is embedded in output returned to the browser, enabling scripts execution in the victim's session context.",
    severity: "HIGH",
    category: "Cross-Site Scripting (XSS)",
    commonCVEs: ["CVE-2024-21626", "CVE-2023-23397"],
    vulnerableExample: `// Thymeleaf HTML - Vulnerable Unescaped Rendering
<div th:utext="\${userInput}">
    <!-- 'utext' renders raw unescaped HTML/JS content -->
</div>`,
    secureExample: `// Thymeleaf HTML - Secure Escaped Rendering
<div th:text="\${userInput}">
    <!-- 'text' automatically escapes HTML dynamic input -->
</div>`,
    remediationExplanation: "Enable contextual output encoding. Use default template engines (like Thymeleaf, ReactJSX, or native text templates) that escape entities automatically. Implement a robust Content Security Policy (CSP) header."
  },
  {
    cweId: "CWE-502",
    name: "Deserialization of Untrusted Data",
    description: "Deserializing user-controlled byte streams can result in arbitrary code execution by invoking malicious execution flow structures.",
    severity: "CRITICAL",
    category: "Insecure Deserialization",
    commonCVEs: ["CVE-2023-22518", "CVE-2021-26084", "CVE-2017-7525"],
    vulnerableExample: `// Java - Vulnerable native deserialization
public Object readObject(byte[] data) throws Exception {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis);
    return ois.readObject(); // Invokes gadget chain triggers
}`,
    secureExample: `// Java - Safe deserialization with Jackson / Safe config
public MyPayload readObjectSecure(String json) throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    // Deny default polymorphic typing
    mapper.deactivateDefaultTyping();
    return mapper.readValue(json, MyPayload.class);
}`,
    remediationExplanation: "Avoid native ObjectInputStream deserialization of untrusted objects entirely. Prefer standard data formats like JSON or Protocol Buffers. Restrict untrusted Java object classes via custom ObjectInputFilters."
  },
  {
    cweId: "CWE-798",
    name: "Use of Hardcoded Credentials",
    description: "The application includes cleartext passwords, API keys, certificate keys or database tokens compiled in source code or static assets.",
    severity: "HIGH",
    category: "Credential Exposure",
    commonCVEs: ["CVE-2023-49070", "CVE-2022-29153"],
    vulnerableExample: `// Java Application Configuration
public class DBConfig {
    private String dbPassword = "SuperSecretProdDBPassword_2026!";
    private String databaseUrl = "jdbc:mysql://db.production.internal:3306/prod";
}`,
    secureExample: `// Java Configuration reading from Environment
@Configuration
public class DBConfig {
    @Value("\${SPRING_DATASOURCE_PASSWORD}")
    private String dbPassword;

    @Value("\${SPRING_DATASOURCE_URL}")
    private String databaseUrl;
}`,
    remediationExplanation: "Never store credentials in code. Retrieve secrets securely at runtime from environment variables, system properties, or designated key vaults (like HashiCorp Vault, AWS Secrets Manager, or Google Cloud Secret Manager)."
  },
  {
    cweId: "CWE-78",
    name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    description: "Raw user input is appended as parameters to operating system commands executed via shell controllers, granting remote command execution permissions.",
    severity: "CRITICAL",
    category: "Injection",
    commonCVEs: ["CVE-2021-44228", "CVE-2022-22965", "CVE-2024-21634"],
    vulnerableExample: `// Java - Vulnerable Runtime exec concatenation
public void executePing(String ipAddress) throws Exception {
    String cmd = "ping -c 3 " + ipAddress;
    Runtime.getRuntime().exec(cmd);
}`,
    secureExample: `// Java - Safe API execution without Command Shell interpretation
public void executePingSecure(String ipAddress) throws Exception {
    // Validate input strictly (IPv4/v6 structure)
    if (!ipAddress.matches("^[a-zA-Z0-9\\\\.]+$")) {
        throw new IllegalArgumentException("Invalid Address");
    }
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", ipAddress);
    pb.start();
}`,
    remediationExplanation: "Avoid running process shells for actions that can be handled natively inside application APIs. If external command execution is unavoidable, validate inputs thoroughly using strict allowlists, and pass inputs as array arguments rather than a single raw shell string."
  },
  {
    cweId: "CWE-352",
    name: "Cross-Site Request Forgery (CSRF)",
    description: "The application doesn't verify whether an incoming request was explicitly initialized by the authenticated user, allowing fraudulent actions via malicious cross-site scripts.",
    severity: "MEDIUM",
    category: "Authentication",
    commonCVEs: ["CVE-2022-25236", "CVE-2021-39144"],
    vulnerableExample: `// Spring Security Vulnerable - CSRF Protection Disabled
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable()); // Unprotected state-changing POST/PUT routes
    return http.build();
}`,
    secureExample: `// Spring Security Secure - Enabled CSRF and Cookie Tokens
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    );
    return http.build();
}`,
    remediationExplanation: "Leverage CSRF synchronizer double-submit cookie tokens. Ensure any state-changing actions (POST, PUT, DELETE, PATCH) validate a valid unique anti-CSRF token. Set session cookies with SameSite=Strict or SameSite=Lax headers."
  },
  {
    cweId: "CWE-918",
    name: "Server-Side Request Forgery (SSRF)",
    description: "The application takes a URL or hostname parameter from the user and attempts to fetch network resources without validating the target destination, potentially scanning internal services.",
    severity: "HIGH",
    category: "Server-Side Request Forgery",
    commonCVEs: ["CVE-2023-38203", "CVE-2021-27850"],
    vulnerableExample: `// Java HTTP request to dynamic user-supplied URL
public String proxyContent(String targetUrl) throws Exception {
    URL url = new URL(targetUrl);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    return IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
}`,
    secureExample: `// Java HTTP request with DNS / Host Target restriction
public String proxyContentSecure(String targetUrl) throws Exception {
    URL url = new URL(targetUrl);
    String host = url.getHost();
    // Validate host does not resolve to private subnets (e.g., 127.0.0.1, 10.0.0.0/8, 169.254.169.254)
    InetAddress addr = InetAddress.getByName(host);
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || host.contains("metadata.google")) {
        throw new SecurityException("Forbidden Destination Subnet");
    }
    // Proceed with validated remote destination proxy
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    return IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
}`,
    remediationExplanation: "Isolate external network handlers. Restrict HTTP requests to a pre-defined white-list of trusted subnets and public API endpoints. Implement DNS resolution validation to block connections trying to resolve local loopbacks or metadata IP regions."
  },
  {
    cweId: "CWE-22",
    name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    description: "The software uses user input to construct files paths, without sanitizing sequence characters like '../', allowing remote attackers to read arbitrary files from storage.",
    severity: "HIGH",
    category: "Broken Access Control",
    commonCVEs: ["CVE-2021-34429", "CVE-2023-32315"],
    vulnerableExample: `// Java - Vulnerable local file fetch
@GetMapping("/download")
public File downloadFile(@RequestParam String filename) {
    return new File("/opt/app/public/files/" + filename); // Attacker sends "../../../etc/passwd"
}`,
    secureExample: `// Java - Path Traversal Protection
@GetMapping("/download")
public Resource downloadFileSecure(@RequestParam String filename) throws Exception {
    Path rootDir = Paths.get("/opt/app/public/files/").toAbsolutePath();
    Path targetPath = rootDir.resolve(filename).normalize();
    
    // Validate target is child of designated root path
    if (!targetPath.startsWith(rootDir)) {
        throw new SecurityException("Access Denied: Path Escape Detected");
    }
    return new UrlResource(targetPath.toUri());
}`,
    remediationExplanation: "Avoid parsing dynamic directories names from users. Keep a secure mapped Index (IDs or hash values) of available files. If dynamic filenames must be ingested, obtain standard normalized paths and assure they strictly begin with the intended root directory."
  },
  {
    cweId: "CWE-611",
    name: "Improper Restriction of XML External Entity Reference (XXE)",
    description: "The XML parser parses document structures which reference external entities, leading to local file reading, internal scanning, or infinite resource crashes.",
    severity: "HIGH",
    category: "Injection",
    commonCVEs: ["CVE-2021-27568", "CVE-2018-1000865"],
    vulnerableExample: `// XML Document Parser with XXE Enabled
public Document parseXml(String incomingXml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder(); // Default XML parsers have XXE enabled
    return db.parse(new InputSource(new StringReader(incomingXml)));
}`,
    secureExample: `// Secure XML Document Parser with DTD disabled
public Document parseXmlSecure(String incomingXml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // Disable external DTDs and stylesheet references completely
    String FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
    dbf.setFeature(FEATURE, true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    return db.parse(new InputSource(new StringReader(incomingXml)));
}`,
    remediationExplanation: "Disable external DTD resolution (External General Entities and External Parameter Entities) inside any XML reading library. Disable Schema validation features or restrict them to secure local catalogs."
  },
  {
    cweId: "CWE-287",
    name: "Improper Authentication",
    description: "The system fails to authenticate the requester or does so weakly, allowing attackers to access administrator profiles or execute privileged commands.",
    severity: "HIGH",
    category: "Authentication",
    commonCVEs: ["CVE-2023-46604", "CVE-2022-21449"],
    vulnerableExample: `// Spring Security - Hardcoded permissive endpoints
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").permitAll() // Administrative paths open to public
        .anyRequest().authenticated()
    );
    return http.build();
}`,
    secureExample: `// Proper Auth filtering
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN") // Restricting privileges to Admin role only
        .anyRequest().authenticated()
    );
    return http.build();
}`,
    remediationExplanation: "Implement standard centralized identity systems. Leverage proven secure frameworks (Spring Security, Auth0, Keycloak) rather than custom verification code blocks. Implement MFA (Multi-Factor Authentication) on administrative dashboards."
  }
];
