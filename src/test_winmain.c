#include <windows.h>
#include <stdio.h>

int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
) {
    // Allocate a console
    AllocConsole();

    // Redirect standard IO to console
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    // Write test output
    printf("Test output from WinMain\n");
    fprintf(stderr, "Test error output from WinMain\n");

    // Flush the output
    fflush(stdout);
    fflush(stderr);

    // Wait for a key press
    printf("\nPress any key to exit...\n");
    fflush(stdout);
    getchar();

    return 0;
}
