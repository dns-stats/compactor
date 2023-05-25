/*
 * Copyright 2016-2017, 2021, 2022 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <iomanip>
#include <vector>
#include <iostream>
#include <string>

#include "queryresponse.hpp"
#include "configuration.hpp"


std::ostream& operator<<(std::ostream& output, const QueryResponse& qr)
{
    const char* transport = NULL;
    const char* transaction_type = NULL;
    bool query = false;
    bool response = false;
    
    if (qr.query_ ) query = true;
    if (qr.response_ ) response = true;
    
    if (query) {
        switch ( qr.query_->transport_type )
        {
        case TransportType::DOH:  transport = "DoH"; break;
        case TransportType::DOT:  transport = "DoT"; break;
        case TransportType::DDOT: transport = "DoD"; break;
        case TransportType::TCP:  transport = "TCP"; break;
        case TransportType::UDP:  transport = "UDP"; break;
        default: transport = "Unknown"; break;
        }

        if ( qr.query_->transaction_type != TransactionType::NONE )
        {
            switch (qr.query_->transaction_type)
            {
            case TransactionType::AUTH_QUERY:           transaction_type =  "Auth query"; break;
            case TransactionType::AUTH_RESPONSE:        transaction_type =  "Auth response"; break;
            case TransactionType::RESOLVER_QUERY:       transaction_type =  "Resolver query"; break;
            case TransactionType::RESOLVER_RESPONSE:    transaction_type =  "Resolver response"; break;
            case TransactionType::CLIENT_QUERY:         transaction_type =  "Client query"; break;
            case TransactionType::CLIENT_RESPONSE:      transaction_type =  "Client response"; break;
            case TransactionType::FORWARDER_QUERY:      transaction_type =  "Forwarder query"; break;
            case TransactionType::FORWARDER_RESPONSE:   transaction_type =  "Forwarder response"; break;
            case TransactionType::STUB_QUERY:           transaction_type =  "Stub query"; break;
            case TransactionType::STUB_RESPONSE:        transaction_type =  "Stub response"; break;
            case TransactionType::TOOL_QUERY:           transaction_type =  "Tool query"; break;
            case TransactionType::TOOL_RESPONSE:        transaction_type =  "Tool response"; break;
            case TransactionType::UPDATE_QUERY:         transaction_type =  "Update query"; break;
            case TransactionType::UPDATE_RESPONSE:      transaction_type =  "Update response"; break;
            default: transaction_type = "Unknown"; break;
            }
        } else
            transaction_type = "Unknown";
    }

    output << "-----------------------------------------------------------------------------------------------------------------------------------\n" ;
    output << "                  Timestamp                   Client IP/port      Server IP/port          QNAME";

    output << "\nQuery     ";
    if (query) {
        std::time_t t = std::chrono::system_clock::to_time_t(qr.query_->timestamp);
        std::tm tm = *std::gmtime(&t);
        char buf[40];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %Hh%Mm%Ss", &tm);
        double us = std::chrono::duration_cast<std::chrono::microseconds>(qr.query_->timestamp.time_since_epoch()).count() % 1000000;
        output << buf << us << "us UTC";
        if ( qr.query_->clientIP )
            output << "    " << *(qr.query_->clientIP) << ":";
        if ( qr.query_->clientPort )
            output << std::left << std::setw(5) << *(qr.query_->clientPort);
        else
            output << "     ";
        if ( qr.query_->serverIP )
            output <<  "  " <<  *(qr.query_->serverIP)  << ":";
        if ( qr.query_->serverPort )
            output << std::left << std::setw(5) << *(qr.query_->serverPort);
        else
            output << "     ";
        if (!qr.query_->dns.queries().empty()) {
            const auto &q = qr.query_->dns.queries().begin();
            output << "  " << CaptureDNS::decode_domain_name(q->dname());
        }
        else
            output << " no QNAME present";
    } else
        output << "No query present";

    output << "\nResponse  ";
    if (response) {
        std::time_t t = std::chrono::system_clock::to_time_t(qr.response_->timestamp);
        std::tm tm = *std::gmtime(&t);
        char buf[40];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %Hh%Mm%Ss", &tm);
        double us = std::chrono::duration_cast<std::chrono::microseconds>(qr.response_->timestamp.time_since_epoch()).count() % 1000000;
        output << buf << us << "us UTC";
        if ( qr.response_->clientIP )
            output << "    " << *(qr.response_->clientIP) << ":";
        if ( qr.response_->clientPort )
            output << std::left << std::setw(5) << *(qr.response_->clientPort);
        else
            output << "     ";
        if ( qr.response_->serverIP )
            output <<  "  " <<  *(qr.response_->serverIP)  << ":";
        if ( qr.response_->serverPort )
            output << std::left << std::setw(5) << *(qr.response_->serverPort);
        else
            output << "     ";
        if (!qr.response_->dns.queries().empty()) {
            const auto &q = qr.response_->dns.queries().begin();
            output << "  " << CaptureDNS::decode_domain_name(q->dname());
        }
        else
            output << " no QNAME present";
    } else
        output << "No response present";

    output << "\n          Transport Hop-limit MsgID QR OPCODE FLAGS(AA/TC/RD/RA/AD/CD)   RCODE  COUNTS(QD/AN/NS/AD)  Query-type  Class Trans-type OPT-codes\n";

    if ( transport )
        output << "             " << transport;
    else
        output << "                ";
    if (query) {
        if ( qr.query_->hoplimit )
            output << "       " << std::left << std::setw(4) << +*(qr.query_->hoplimit);
        else
            output << "           ";
        output << "   " << std::left << std::setw(5) << qr.query_->dns.id();
        output << "  0 ";
        output << std::left <<  std::setw(6) << Configuration::find_opcode_string(qr.query_->dns.opcode()) << "       " ;
        output <<  (qr.query_->dns.authoritative_answer() ? " 1 " : " 0 ") ;
        output <<  (qr.query_->dns.truncated()            ? " 1 " : " 0 ") ;
        output <<  (qr.query_->dns.recursion_desired()    ? " 1 " : " 0 ") ;
        output <<  (qr.query_->dns.recursion_available()  ? " 1 " : " 0 ") ;
        output <<  (qr.query_->dns.authenticated_data()   ? " 1 " : " 0 ") ;
        output <<  (qr.query_->dns.checking_disabled()    ? " 1 " : " 0 ") ;
        output << "  "  << std::left  << std::setw(11) << Configuration::find_rcode_string(qr.query_->dns.rcode()) << "   " ;
        output <<  " " << std::right << std::setw(2) << qr.query_->dns.questions_count();
        output <<  " " << std::right << std::setw(2) << qr.query_->dns.answers_count();
        output <<  " " << std::right << std::setw(2) << qr.query_->dns.authority_count();
        output <<  " " << std::right << std::setw(2) << qr.query_->dns.additional_count();

        if (!qr.query_->dns.queries().empty()) {
            const auto &q = qr.query_->dns.queries().begin();
            output << "   " << std::setw(6) << Configuration::find_rrtype_string(q->query_type());
            output << "        " << static_cast<unsigned>(q->query_class());
        }
        if ( transaction_type )
            output << "    " << transaction_type << "    ";
        auto edns0 = qr.query_->dns.edns0();
        if ( edns0 )
        {
          auto options = edns0->options();
          if ( !options.empty() )
          {
            for ( auto& opt : options )
            {
                output << opt.code() << " ";
            }
          }
          else
            output << "None";
        }
        else
            output << "None";
        output << "\n";
    }
    else
        output << "\n";

    if (response) {
        output << "                           ";
        output << "   " << std::left << std::setw(5) << qr.response_->dns.id();
        output << "  1 ";
        output << std::left <<  std::setw(6) << Configuration::find_opcode_string(qr.response_->dns.opcode()) << "       " ;
        output <<  (qr.response_->dns.authoritative_answer() ? " 1 " : " 0 ") ;
        output <<  (qr.response_->dns.truncated()            ? " 1 " : " 0 ") ;
        output <<  (qr.response_->dns.recursion_desired()    ? " 1 " : " 0 ") ;
        output <<  (qr.response_->dns.recursion_available()  ? " 1 " : " 0 ") ;
        output <<  (qr.response_->dns.authenticated_data()   ? " 1 " : " 0 ") ;
        output <<  (qr.response_->dns.checking_disabled()    ? " 1 " : " 0 ") ;
        output << "  "  << std::left  << std::setw(11) << Configuration::find_rcode_string(qr.response_->dns.rcode()) << "   " ;
        output <<  " " << std::right << std::setw(2) << qr.response_->dns.questions_count();
        output <<  " " << std::right << std::setw(2) << qr.response_->dns.answers_count();
        output <<  " " << std::right << std::setw(2) << qr.response_->dns.authority_count();
        output <<  " " << std::right << std::setw(2) << qr.response_->dns.additional_count();

        if (!qr.response_->dns.queries().empty()) {
            const auto &q = qr.response_->dns.queries().begin();
            output << "   " << std::setw(6) << Configuration::find_rrtype_string(q->query_type());
            output << "        " << static_cast<unsigned>(q->query_class());
        }
        if ( transaction_type )
            output << "    " << transaction_type;
        output << "\n";
    }
    else
        output << "\n";

    output << "\n";
    return output;


}
