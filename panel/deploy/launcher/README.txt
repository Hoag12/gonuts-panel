GoNuts panel launcher
=====================

This JAR bundles Linux arm64 and amd64 builds of the GoNuts panel. It requires
Java 17 or newer and a Linux host.

Run:
  java -jar gonuts-panel.jar

Then configure the same GONUTS_* environment variables documented in
panel/README.md. The native binary is smaller and is recommended for the NAS;
this JAR is provided as an optional, Java-consistent artifact.

The launcher extracts the matching binary to a temporary directory, runs it
with inherited stdio, and removes the temporary file on exit.
