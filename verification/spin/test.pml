/* Base class for defining our protocol later (currently just tests). */

// Demo two-party communication (ABP).
// IPC is modeled via channels:
//
// chan <name> = [<dim>] of {<t_1>, <t_2>, ... , <t_n>};
//      |_ channel name
//                  |_ num elements to transmit
//                              |_ type of elements on channel
//
// Sending message:     ch ! <expr_n>;
// Receiving message:   ch ? <const_n>;
//

mtype {MSG, ACK};

chan toS = [2] of {mtype, bit};
chan toR = [2] of {mtype, bit};

// Sender sends a message to channel (length 2).
proctype Sender(chan in, out)
{
    bit sendbit, recvbit;
    do
    :: out ! MSG, sendbit ->
        in ? ACK, recvbit;
        if
        :: recvbit == sendbit ->
            sendbit = 1-sendbit
        :: else
        fi
    od
}

proctype Receiver(chan in, out)
{
    bit recvbit;
    do
    :: in ? MSG(recvbit) ->
        out ! ACK(recvbit);
    od
}

init
{
    printf("[init] Starting Sender() and Receiver()...\n");
    run Sender(toS, toR);
    run Receiver(toR, toS);
}
