When a header proposal is made, a header with name *header_name* will be added so long as the following conditions are met:

1. *header_name* has not been [staged for removal](removeHeader)
2. *header_name* has not already been set

If both these conditions fail to be met then the header proposal will fail, and no action will be taken.