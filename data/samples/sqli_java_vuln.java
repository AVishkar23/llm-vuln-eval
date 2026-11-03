import java.sql.*;

public class UserDao {
    public ResultSet findUser(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(query);
    }
}
