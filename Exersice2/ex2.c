#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <mta_rand.h>
#include <mta_crypt.h>

pthread_cond_t cond_guessed_password = PTHREAD_COND_INITIALIZER;

pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_guessed_password = PTHREAD_MUTEX_INITIALIZER;

pthread_attr_t decrypt_attr;
pthread_attr_t encrypt_attr;

typedef struct
{
    char *Password;
    int Index;
} GuessedPassword;

typedef struct
{
    int NumOfDecrypters;
    int TimeOut;
    unsigned int PasswordLength;
} Data;

char *PASSWORD;
unsigned int PASSWORD_LENGTH;
GuessedPassword GUESSED_PASSWORD;
int IS_CREATE = 0;

int validate_input(int size, char *input[], Data *data);
int validate_parameter(int size, char *input[], int *parameter, char *toCompare1, char *toCompare2);
int CheckPassword(char *RealPassword);
void UntilPrintable(char *password, unsigned int length);
void CheckPrintable(char *password, unsigned int length, int *isPrintable);
void AllocationTest(void *ptr);
void PrintMsg(char *msg);
int HandleGuessedPassword(char *buffer, char *RealPassword, int *guessed, time_t seconds);
void *DecrypterJob(void *args);
void *EncrypterJob(void *args);

int main(int argc, char *argv[])
{
    pthread_t Encrypter;

    assert(pthread_attr_init(&decrypt_attr) == 0);
    assert(pthread_attr_init(&encrypt_attr) == 0);

    struct sched_param encrypter_priority = {sched_get_priority_max(SCHED_FIFO)};
    struct sched_param decrypter_priority = {sched_get_priority_min(SCHED_FIFO)};

    //Set encrypt_attr priority
    assert(pthread_attr_setschedpolicy(&encrypt_attr, SCHED_FIFO) == 0);
    assert(pthread_attr_setschedparam(&encrypt_attr, &encrypter_priority) == 0);
    assert(pthread_attr_setinheritsched(&encrypt_attr, PTHREAD_EXPLICIT_SCHED) == 0);

    //Set decrypt_attr priority
    assert(pthread_attr_setschedpolicy(&decrypt_attr, SCHED_FIFO) == 0);
    assert(pthread_attr_setschedparam(&decrypt_attr, &decrypter_priority) == 0);
    assert(pthread_attr_setinheritsched(&decrypt_attr, PTHREAD_EXPLICIT_SCHED) == 0);
    
    int i;
    Data data;
    data.TimeOut = 0;
    GUESSED_PASSWORD.Index = -1;

    if (validate_input(argc, argv, &data) == 0)
    {
        PrintMsg("Invalid Input!\n");
        exit(1);
    }

    int indeces[data.NumOfDecrypters];

    PASSWORD = (char *)malloc(sizeof(char) * data.PasswordLength);
    AllocationTest(PASSWORD);

    GUESSED_PASSWORD.Password = (char *)malloc(sizeof(char) * data.PasswordLength);
    AllocationTest(GUESSED_PASSWORD.Password);

    pthread_t Decrypter[data.NumOfDecrypters];

    if (pthread_create(&Encrypter, &encrypt_attr, EncrypterJob, (void *)&data) != 0)
    {
        PrintMsg("Encrypter thread created failed!\n");
        exit(1);
    }

    while (IS_CREATE == 0)
    { // wait until a password had generated
        sleep(1);
    }

    for (i = 0; i < data.NumOfDecrypters; i++)
    {
        indeces[i] = i + 1;
        if (pthread_create(&Decrypter[i], &decrypt_attr, DecrypterJob, (void *)&indeces[i]) != 0)
        {
            PrintMsg("Decrypter thread created failed!\n");
            exit(1);
        }
    }

    if (pthread_join(Encrypter, NULL) != 0)
    {
        PrintMsg("Join encrypter failed\n");
        exit(1);
    }

    pthread_attr_destroy(&decrypt_attr);
    pthread_attr_destroy(&encrypt_attr);
    return 0;
}

void *DecrypterJob(void *args)
{
    int index = *(int *)args;
    MTA_CRYPT_RET_STATUS status = MTA_CRYPT_RET_OK;
    char key[100];
    char password[PASSWORD_LENGTH];
    int i, isPrintable, counter = 0;
    char buffer[255], encryptedPassword[PASSWORD_LENGTH];
    unsigned int retLength;
    time_t seconds;
    srand(time(0));

    while (1)
    {
        if (memcmp(encryptedPassword, PASSWORD, PASSWORD_LENGTH) != 0)
        {
            memcpy(encryptedPassword, PASSWORD, PASSWORD_LENGTH);
            counter = 0;
        }

        isPrintable = 1;
        MTA_get_rand_data(key, (unsigned int)(PASSWORD_LENGTH / 8));

        status = MTA_decrypt(key, (unsigned int)(PASSWORD_LENGTH / 8), PASSWORD, PASSWORD_LENGTH, password, &retLength);
        password[retLength] = '\0';

        if (status != MTA_CRYPT_RET_OK)
        {
            PrintMsg("Unable to encrypt new password!\n");
            exit(status);
        }

        if (retLength != PASSWORD_LENGTH)
        {
            sprintf(buffer, "%ld\t[DECRYPTER #%d]\t[INFO]\tUnmatched length returned from so function %d != %d\n", seconds, index, retLength, PASSWORD_LENGTH);
            PrintMsg(buffer);
        }

        CheckPrintable(password, retLength, &isPrintable);

        if (isPrintable != 0)
        {
            while (1)
            {
                pthread_mutex_lock(&mutex_guessed_password);

                if (GUESSED_PASSWORD.Index == -1)
                {
                    GUESSED_PASSWORD.Index = index;
                    memcpy(GUESSED_PASSWORD.Password, password, PASSWORD_LENGTH);
                    time(&seconds);
                    sprintf(buffer, "%ld\t[DECRYPTER #%d]\t[INFO]\tAfter decryption(%s), key guessed(%s), sending to encryptor after %d iterations\n", seconds, index, password, key, counter);
                    PrintMsg(buffer);
                    pthread_mutex_unlock(&mutex_guessed_password);
                    break;
                }
                else
                {
                    pthread_mutex_unlock(&mutex_guessed_password);
                }

                pthread_cond_signal(&cond_guessed_password);
                usleep(30000);
            }
        }

        counter++;
    }

    return NULL;
}

void *EncrypterJob(void *args)
{
    Data *data = (Data *)args;
    char RealPassword[data->PasswordLength];
    char Key[100] = {0};
    char buffer[255];
    int guessed;
    MTA_CRYPT_RET_STATUS status = MTA_CRYPT_RET_OK;
    struct timespec timeout;
    time_t seconds;
    srand(time(0));

    while (1)
    {
        guessed = 0;
        UntilPrintable(RealPassword, data->PasswordLength);

        MTA_get_rand_data(Key, (unsigned int)(data->PasswordLength / 8));
        status = MTA_encrypt(Key, (unsigned int)(data->PasswordLength / 8), RealPassword, data->PasswordLength, PASSWORD, &PASSWORD_LENGTH);

        if (status != MTA_CRYPT_RET_OK)
        {
            PrintMsg("Unable to encrypt new password!\n");
            exit(status);
        }

        IS_CREATE = 1; // tell to main that it is ok to create the desrypters

        time(&seconds);
        sprintf(buffer, "%ld\t[ENCRYPTER]\t[INFO]\tNew password generated: %s, key: %s, After encryption %s\n", seconds, RealPassword, Key, PASSWORD);
        PrintMsg(buffer);

        GUESSED_PASSWORD.Index = -1;
        if (data->TimeOut != 0)
        {
            clock_gettime(CLOCK_REALTIME, &timeout);
            timeout.tv_sec += data->TimeOut;

            while (pthread_cond_timedwait(&cond_guessed_password, &mutex_guessed_password, &timeout) != ETIMEDOUT)
            {
                if (HandleGuessedPassword(buffer, RealPassword, &guessed, seconds) == 1)
                {
                    pthread_mutex_unlock(&mutex_guessed_password);
                    break;
                }

                pthread_mutex_unlock(&mutex_guessed_password);
                GUESSED_PASSWORD.Index = -1;
            }

            if (guessed == 0)
            {
                time(&seconds);
                sprintf(buffer, "%ld\t[ENCRYPTER]\t[ERROR]\tNo password received during the configured time period (%d second), regenerating password\n", seconds, data->TimeOut);
                PrintMsg(buffer);
            }
        }
        else
        { // no timeout
            while (1)
            {
                GUESSED_PASSWORD.Index = -1;
                pthread_cond_wait(&cond_guessed_password, &mutex_guessed_password);

                if (HandleGuessedPassword(buffer, RealPassword, NULL, seconds) == 1)
                {
                    pthread_mutex_unlock(&mutex_guessed_password);
                    break;
                }

                pthread_mutex_unlock(&mutex_guessed_password);
            }
        }
    }

    return NULL;
}

void UntilPrintable(char *password, unsigned int length)
{
    int i, isPrintable = 0;

    for (int i = 0; i < length; i++)
    {
        do
        {
            password[i] = MTA_get_rand_char();
            isPrintable = isprint(password[i]);
        } while (isPrintable == 0);
    }
}

void CheckPrintable(char *password, unsigned int length, int *isPrintable)
{
    int i;

    for (i = 0; i < length; i++)
    {
        *isPrintable = isprint(password[i]);

        if (*isPrintable == 0)
        {
            break;
        }
    }
}

int HandleGuessedPassword(char *buffer, char *RealPassword, int *guessed, time_t seconds)
{
    int res = 0;

    if (CheckPassword(RealPassword) == 1)
    {
        time(&seconds);
        sprintf(buffer, "%ld\t[ENCRYPTER]\t[OK]\tpassword decrypted successfully by decryptor #%d, received(%s), is (%s)\n", seconds, GUESSED_PASSWORD.Index, GUESSED_PASSWORD.Password, RealPassword);
        PrintMsg(buffer);

        if (guessed != NULL)
        {
            *guessed = 1;
        }

        res = 1;
    }
    else
    {
        time(&seconds);
        sprintf(buffer, "%ld\t[ENCRYPTER]\t[ERROR]\tWorng password received from decrypter %d(%s), should be (%s)\n", seconds, GUESSED_PASSWORD.Index, GUESSED_PASSWORD.Password, RealPassword);
        PrintMsg(buffer);
    }

    return res;
}

int CheckPassword(char *RealPassword)
{
    return memcmp(GUESSED_PASSWORD.Password, RealPassword, PASSWORD_LENGTH) == 0;
}

int validate_input(int size, char *input[], Data *data)
{
    if (validate_parameter(size, input, &(data->NumOfDecrypters), "-n", "--num-of-decrypters") == 0)
    {
        return 0;
    }
    if (validate_parameter(size, input, &data->PasswordLength, "-l", "--password-length") == 0)
    {
        return 0;
    }
    if (size == 7)
    {
        if (validate_parameter(size, input, &(data->TimeOut), "-t", "--timeout") == 0)
        {
            return 0;
        }
    }

    return data->PasswordLength % 8 == 0 && data->PasswordLength > 0;
}

int validate_parameter(int size, char *input[], int *parameter, char *toCompare1, char *toCompare2)
{
    int i, res = 0;

    for (i = 0; i < size; i++)
    {
        if (strcmp(input[i], toCompare1) == 0 || (strcmp(input[i], toCompare2) == 0))
        {
            *parameter = atoi(input[++i]);
            res = 1;
            break;
        }
    }

    return res;
}

void PrintMsg(char *msg)
{
    pthread_mutex_lock(&mutex_print);
    printf("%s", msg);
    pthread_mutex_unlock(&mutex_print);
}

void AllocationTest(void *ptr)
{
    if (ptr == NULL)
    {
        PrintMsg("Allocation error!\n");
        exit(1);
    }
}