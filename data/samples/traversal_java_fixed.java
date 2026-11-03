import java.nio.file.*;
import java.io.IOException;

public class FileStore {
    private final Path baseDir = Paths.get("/var/www/files");

    public String read(String fileName) throws IOException {
        Path path = baseDir.resolve(fileName).normalize();
        if (!path.startsWith(baseDir)) {
            throw new SecurityException("path escapes base directory");
        }
        return Files.readString(path);
    }
}
