#ifndef BR_BUNDLE_IDENTITY_H
#define BR_BUNDLE_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// Some signing/install tools append a ten-character Apple team identifier.
// Scope the storage fallback to the root app, with only that optional suffix.
static inline bool BRBundleIdentityAllowsSandboxFallback(const char *identifier) {
    static const char root[] = "com.ayato.bereal493";
    const size_t rootLength = sizeof(root) - 1;
    if (identifier == NULL) return false;
    if (strcmp(identifier, root) == 0) return true;
    if (strlen(identifier) != rootLength + 1 + 10 ||
        strncmp(identifier, root, rootLength) != 0 || identifier[rootLength] != '.') return false;
    for (size_t index = rootLength + 1; index < rootLength + 1 + 10; ++index) {
        const unsigned char character = (unsigned char)identifier[index];
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9'))) return false;
    }
    return true;
}

#endif
