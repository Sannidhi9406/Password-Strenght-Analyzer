package cybersecurity;
import java.io.Console;
import java.util.*;
import java.util.regex.Pattern;

public class PasswordAnalyzer {

    // ---------- Step 1: Policy ----------
    static final int MIN_LENGTH = 12;
    static final Set<String> COMMON_PASSWORDS =
            Set.of("password", "123456", "qwerty", "admin", "letmein", "welcome");

    // ---------- Step 2: Regex patterns (compiled once) ----------
    static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    static final Pattern DIGIT     = Pattern.compile("\\d");
    static final Pattern SPECIAL   = Pattern.compile("[^A-Za-z0-9]");
    static final Pattern REPEATS   = Pattern.compile("(.)\\1{2,}"); // e.g. "aaa"

    static Map<String, Boolean> checkRules(String password) {
        Map<String, Boolean> rules = new LinkedHashMap<>();
        rules.put("length",     password.length() >= MIN_LENGTH);
        rules.put("lowercase",  LOWERCASE.matcher(password).find());
        rules.put("uppercase",  UPPERCASE.matcher(password).find());
        rules.put("digit",      DIGIT.matcher(password).find());
        rules.put("special",    SPECIAL.matcher(password).find());
        rules.put("no_repeats", !REPEATS.matcher(password).find());
        return rules;
    }

    // ---------- Step 3: Scoring ----------
    static int scorePassword(String password, Map<String, Boolean> rules) {
        int score = 0;
        for (boolean passed : rules.values()) {
            if (passed) score++;
        }
        if (password.length() >= 16) score++;                    // bonus for length
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) score = 0;
        return score;
    }

    static String rate(int score) {
        if (score <= 2) return "Weak";
        if (score <= 4) return "Medium";
        if (score <= 6) return "Strong";
        return "Very Strong";
    }

    // ---------- Step 4: Feedback ----------
    static final Map<String, String> FEEDBACK = Map.of(
            "length",     "Use at least " + MIN_LENGTH + " characters.",
            "lowercase",  "Add lowercase letters (a-z).",
            "uppercase",  "Add uppercase letters (A-Z).",
            "digit",      "Add at least one number.",
            "special",    "Add a special character (e.g. ! @ # $ %).",
            "no_repeats", "Avoid repeating the same character 3+ times."
    );

    static List<String> getSuggestions(Map<String, Boolean> rules) {
        List<String> tips = new ArrayList<>();
        for (Map.Entry<String, Boolean> rule : rules.entrySet()) {
            if (!rule.getValue()) tips.add(FEEDBACK.get(rule.getKey()));
        }
        return tips;
    }

    // ---------- Step 5: Main loop ----------
    static String readPassword(Scanner scanner) {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("%nEnter a password (or press Enter to quit): ");
            return chars == null ? "" : new String(chars);
        }
        // Fallback for IDEs where System.console() is null (password will be visible)
        System.out.print("\nEnter a password (or press Enter to quit): ");
        return scanner.hasNextLine() ? scanner.nextLine() : "";
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Password Strength Analyzer ===");

        while (true) {
            String password = readPassword(scanner);
            if (password.isEmpty()) break;

            Map<String, Boolean> rules = checkRules(password);
            int score = scorePassword(password, rules);

            System.out.println("Strength: " + rate(score) + " (" + score + "/7)");

            if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
                System.out.println("This is a very common password. Never use it!");
            }
            for (String tip : getSuggestions(rules)) {
                System.out.println("  - " + tip);
            }
            if (!rules.containsValue(false)) {
                System.out.println("Great job! This password meets the policy.");
            }
        }
        System.out.println("Goodbye!");
    }
}