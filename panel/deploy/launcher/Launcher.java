import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Optional Linux launcher for the bundled panel binaries. The native binary is
 * recommended; this JAR exists so the release has a Java-consistent artifact.
 */
public final class Launcher {
    private Launcher() { }

    public static void main(String[] args) throws Exception {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (!os.contains("linux")) {
            System.err.println("The bundled panel binaries are Linux only. Use the Docker image or build from source.");
            System.exit(2);
        }
        String bin = arch.contains("aarch64") || arch.contains("arm64")
                ? "gonuts-panel-linux-arm64"
                : arch.contains("amd64") || arch.contains("x86_64")
                ? "gonuts-panel-linux-amd64"
                : null;
        if (bin == null) {
            System.err.println("Unsupported architecture: " + arch);
            System.exit(2);
        }
        Path dir = Files.createTempDirectory("gonuts-panel-");
        Path out = dir.resolve(bin);
        try (InputStream in = Launcher.class.getResourceAsStream("/bin/" + bin)) {
            if (in == null) {
                System.err.println("Bundled binary missing: " + bin);
                System.exit(2);
            }
            Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
        }
        try {
            Files.setPosixFilePermissions(out, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems: the executable bit is already implied.
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                Files.deleteIfExists(out);
                Files.deleteIfExists(dir);
            } catch (IOException ignored) {
                // Best-effort cleanup of the extracted temporary binary.
            }
        }));
        List<String> command = new ArrayList<>();
        command.add(out.toString());
        command.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(command).inheritIO().start();
        System.exit(process.waitFor());
    }
}
