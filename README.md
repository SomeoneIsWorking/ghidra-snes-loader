-------

# ghidra-snes-loader
Loader for SNES ROMs.  Works with Ghidra v12.0.4.
Work of several People, not mine alone.

## To Build and Install

Builds are done via Gradle, with the `GHIDRA_INSTALL_DIR` environment variable set to the path of
Ghidra installation.

Linux:
1. `cd` to the `SnesLoader` directory.
2. Run `GHIDRA_INSTALL_DIR='/some/absolute/path' ./gradlew buildExtension`.

Windows:
1. `cd` to the `SnesLoader` directory.
2. Run `set GHIDRA_INSTALL_DIR="C:\some\absolute\path" && gradlew.bat buildExtension`.

Windows Powershell:
1. `cd` to the `SnesLoader` directory.
2. Run 'set GHIDRA_INSTALL_DIR="C:\some\absolute\path\ghidra_12.0.4_PUBLIC" | .\gradlew.bat buildExtension'
   
The built extension is in the `dist` directory.
1. Copy it into `GHIDRA_INSTALL_DIR/Extensions/Ghidra/`.
2. Start Ghidra
3. File\Install Extension
4. Select the SnesLoader, add a mark
5. Press OK and restart Ghidra completly


## To Develop with Eclipse

The repo doesn't contain any Eclipse project files, but we can generate them with Gradle.
If you have an Eclipse workspace with an older version of the project, remove the project from the
workspace before doing this.

Linux:
1. `cd` to the `SnesLoader` directory.
2. Run `GHIDRA_INSTALL_DIR='/some/absolute/path' ./gradlew cleanEclipse`.
3. Run `GHIDRA_INSTALL_DIR='/some/absolute/path' ./gradlew eclipse`.

Windows:
1. `cd` to the `SnesLoader` directory.
2. Run `set GHIDRA_INSTALL_DIR="C:\some\absolute\path" && gradlew.bat cleanEclipse`.
3. Run `set GHIDRA_INSTALL_DIR="C:\some\absolute\path" && gradlew.bat eclipse`.

Then in Eclipse: File --> Import --> Existing Projects into Workspace.
Select the `SnesLoader` directory.

Right-click the SnesLoader project in the project explorer, choose
GhidraDev --> Link Ghidra...
