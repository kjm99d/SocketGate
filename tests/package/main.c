/* Smoke test of an installed SockGate package: both C APIs link and run. */
#include <sockgate/client.h>
#include <sockgate/server.h>

#include <stdio.h>

int main(void)
{
    SG_ClientConfig config;
    SG_Client* client = NULL;
    SG_Status st;
    SG_ClientConfig_Init(&config);
    config.identity_name = "consumer";
    config.key_store_type = SG_KEYSTORE_MEMORY;
    st = SG_Client_Create(&config, &client);
    printf("client api %u server api %u create=%s\n", SG_Client_GetApiVersion(), SG_Server_GetApiVersion(),
           SG_StatusString(st));
    SG_Client_Destroy(client);
    return st == SG_OK ? 0 : 1;
}
