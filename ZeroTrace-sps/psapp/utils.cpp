
#include <stdio.h>
#include <cstring>

#include "utils.h"
#include "app.h"


void info_print(const char* str) {
    printf("[INFO] %s\n", str);
}

void warning_print(const char* str) {
    printf("[WARNING] %s\n", str);
}

void error_print(const char* str) {
    printf("[ERROR] %s\n", str);
}

void test_print(const char* str) {
    printf("[TEST] %s\n", str);
}

void exp_print(const char* str) {
    printf("[EXP] %s\n", str);
}

int is_error(int error_code) {
    char err_message[100];

    switch(error_code) {
        case RET_SUCCESS:
            return 0;

        case ERROR_INVALID_ARGUMENTS:
            sprintf(err_message, "Arguments should match one of the data types in datatypes.h");
            break;

        case ERROR_ORAM_RETURN_ERROR:
            sprintf(err_message, "ORAM returned error");
            break;

        case ERROR_USER_AUTH_FAILED:
            sprintf(err_message, "User authentication failed in receive");
            break;

        case ERROR_SERVICE_RUNNING:
            sprintf(err_message, "Signal service is already running");
            break;

        case ERROR_SERVICE_NOT_RUNNING:
            sprintf(err_message, "Signal service is not yet started");
            break;

        case ERROR_OCALL_FAILED:
            sprintf(err_message, "ORAM ocall failed");
            break;

        case ERROR_BUCKET_SIZE_INCONSISTENT:
            sprintf(err_message, "ORAM encrypted bucket size inconsistent");
            break;

        case ERROR_ORAM_INDEX_OOR:
            sprintf(err_message, "ORAM index out of range");
            break;

        case ERROR_ORAM_ENCRYPTION_FAILED:
            sprintf(err_message, "ORAM encryption/decryption failed");
            break;

        case ERROR_SERVICE_DECRYPTION_FAILED:
            sprintf(err_message, "Signal service unable to decrypt ecall inputs");
            break;

        case ERROR_VARIABLE_SIZE_INCONSISTENT:
            sprintf(err_message, "Somewhere size is invalid");
            break;

        default:
            sprintf(err_message, "Unknown error."); 
    }

    error_print(err_message);
    return 1;
}


void show_version() {
	printf("\n\nScalable Private Signaling (using Intel SGX) v%s\n\n", VERSION);
}
