/*
 *
 *  Copyright 2026 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */



#include <iostream>
#include <string>
#include <map>
#include <cstring>
#include "fsm.h"

using namespace std;



map<string, system_state_t> state_map = {
    {"INIT_STATE", INIT_STATE},
    {"DISCOVERED_STATE", DISCOVERED_STATE},
    {"MODE_SET_ENABLED_STATE", MODE_SET_ENABLED_STATE},
    {"CORE_CONN_CREATED_STATE", CORE_CONN_CREATED_STATE},
    {"CORE_CONN_CLOSED_STATE", CORE_CONN_CLOSED_STATE}
};

map<string, system_event_t> event_map = {
    {"NFCEE_DISCOVER_EVENT", NFCEE_DISCOVER_EVENT},
    {"DISCOVER_TDA_EVENT", DISCOVER_TDA_EVENT},
    {"OPEN_TDA_EVENT", OPEN_TDA_EVENT},
    {"CORE_CONN_CREATE_EVENT", CORE_CONN_CREATE_EVENT},
    {"TRANSCEIVE_EVENT", TRANSCEIVE_EVENT},
    {"CLOSE_TDA_EVENT", CLOSE_TDA_EVENT},
    {"CORE_CONN_CLOSE_EVENT", CORE_CONN_CLOSE_EVENT}
};



int main(int argc, char* argv[]) {


    if (argc != 3) {
        cout << "Usage: ./tda_sm_test <STATE> <EVENT>\n";
        return -1;
    }

    string state_str = argv[1];
    string event_str = argv[2];


    if (state_map.find(state_str) == state_map.end()) {
        cout << "Invalid STATE: " << state_str << endl;
        return -1;
    }

    if (event_map.find(event_str) == event_map.end()) {
        cout << "Invalid EVENT: " << event_str << endl;
        return -1;
    }


    system_state_t state = state_map[state_str];
    system_event_t event = event_map[event_str];

    cout << "-------------------------------------" << endl;
    cout << "Running Test:" << endl;
    cout << "STATE : " << state_str << endl;
    cout << "EVENT : " << event_str << endl;


    update_state(state);


    fp_event_handler_t handler = handle_event(event);


    if (handler != NULL) {

        cout << "Handler found → Executing..." << endl;

        int ret = handler(NULL);   // assuming int return

        cout << "Handler returned: " << ret << endl;
        cout << "TEST RESULT: PASS" << endl;

    } else {
        cout << "No handler found for given STATE + EVENT" << endl;
        cout << "TEST RESULT: FAIL" << endl;
    }

    cout << "-------------------------------------" << endl;

    return 0;
}