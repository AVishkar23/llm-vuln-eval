import java.sql.*;

public class UserDao {
    public ResultSet findUser(Connection conn, String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, username);
        return stmt.executeQuery();
    }
}
