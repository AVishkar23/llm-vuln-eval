public class DbConfig {
    private static final String DB_PASSWORD = "P@ssw0rd!prod";

    public String password() {
        return DB_PASSWORD;
    }
}
