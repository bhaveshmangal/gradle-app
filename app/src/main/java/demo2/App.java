import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.bind.annotation.PathVariable;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@Controller
public class App {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }

    // DataSource configuration for H2 database
    @Bean
    public DataSource dataSource() {
        JdbcDataSource ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1");
        ds.setUser("sa");
        ds.setPassword("password");
        return ds;
    }

    // Initialize database schema and data
    @PostConstruct
    public void initDb() {
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS entries (id INT AUTO_INCREMENT, title VARCHAR(255), description TEXT, text TEXT, date DATE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS img (id INT AUTO_INCREMENT, link VARCHAR(255))");
    }

    // Home page endpoint
    @GetMapping("/")
    public String index(Model model) {
        List<Map<String, Object>> entries = jdbcTemplate.queryForList("SELECT * FROM entries ORDER BY id DESC");
        model.addAttribute("entries", entries);
        return "index";
    }

    // SQL Injection vulnerability in /img/{id} endpoint
    @GetMapping("/img/{id}")
    public String getImageById(@PathVariable("id") String id, Model model) {
        String query = "SELECT id, link FROM img WHERE id = " + id; // SQL injection vulnerability
        List<Map<String, Object>> images = jdbcTemplate.queryForList(query);
        model.addAttribute("images", images);
        return "img";
    }

    // XSS vulnerability in /search endpoint
    @GetMapping("/search")
    public String search(@RequestParam("u") String name, Model model) {
        String output = "Hello " + name + "!"; // XSS vulnerability if name contains HTML/JavaScript
        model.addAttribute("output", output);
        return "search";
    }

    // OS Command Injection vulnerability in /website endpoint
    @GetMapping("/website")
    @ResponseBody
    public String executeCommand(@RequestParam("u") String url) {
        try {
            Process process = Runtime.getRuntime().exec("curl " + url); // OS command injection
            process.waitFor();
            return "Executed: " + url;
        } catch (Exception e) {
            return "Error executing command";
        }
    }

    // Open redirect vulnerability in /redirect endpoint
    @GetMapping("/redirect")
    public String unsafeRedirect(@RequestParam("url") String url) {
        return "redirect:" + url; // Open redirect vulnerability
    }

    // Insecure file upload vulnerability in /upload endpoint
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            file.transferTo(new File("uploads/" + file.getOriginalFilename())); // Path traversal vulnerability
            jdbcTemplate.update("INSERT INTO img (link) VALUES (?)", file.getOriginalFilename());
            return "File uploaded successfully";
        } catch (IOException e) {
            return "Error uploading file";
        }
    }

    // Login endpoint with hardcoded credentials and session management issues
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam("username") String username,
                        @RequestParam("password") String password, HttpSession session) {
        if ("admin".equals(username) && "p@ssword".equals(password)) { // Hardcoded credentials
            session.setAttribute("user", username);
            return "redirect:/";
        } else {
            return "Invalid credentials";
        }
    }

    // Logout endpoint
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }
}
