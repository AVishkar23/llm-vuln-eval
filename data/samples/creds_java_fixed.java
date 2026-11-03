public class DbConfig {
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    public String password() {
        return DB_PASSWORD;
    }
}
