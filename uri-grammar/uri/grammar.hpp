// -*- Mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 78 -*-
//
// uri_grammar
//
// Copyright 2010  Braden McDaniel
//
// Distributed under the Boost Software License, Version 1.0.
//
// See accompanying file COPYING or copy at
// http://www.boost.org/LICENSE_1_0.txt
//

# ifndef URI_GRAMMAR_HPP
#   define URI_GRAMMAR_HPP

#   include <boost/fusion/include/boost_array.hpp>
#   include <boost/fusion/include/std_pair.hpp>
#   include <boost/spirit/include/qi.hpp>
#   include <boost/spirit/include/phoenix.hpp>

namespace uri {

    template <typename Iterator>
    struct ipv4_grammar :
        boost::spirit::qi::grammar<Iterator, std::uint32_t()> {

        ipv4_grammar(): ipv4_grammar::base_type(ipv4address)
        {
            using boost::spirit::qi::eps;
            using boost::spirit::qi::_1;
            using boost::spirit::qi::_val;
            using std::uint32_t;

            ipv4address
                =   eps[_val = 0]
                    >> dec_octet[_val  = (_1 << 24)] >> '.'
                    >> dec_octet[_val |= (_1 << 16)] >> '.'
                    >> dec_octet[_val |= (_1 << 8) ] >> '.'
                    >> dec_octet[_val |= _1]
                ;

            dec_octet
                =   boost::spirit::qi::uint_parser<std::uint8_t, 10, 1, 3>()
                ;
        }

        //
        // dec_octet needs a uint32_t attribute so that bit shifting will work
        // properly.
        //
        boost::spirit::qi::rule<Iterator, std::uint32_t()> ipv4address,
            dec_octet;
    };

    template <typename Iterator>
    struct ipv6_grammar :
        boost::spirit::qi::grammar<Iterator, boost::spirit::qi::locals<unsigned>, boost::array<std::uint16_t, 8>()> {

        ipv6_grammar(): ipv6_grammar::base_type(ipv6address)
        {
            using std::uint16_t;
            using std::uint64_t;
            using boost::array;
            using boost::spirit::qi::eps;
            using boost::spirit::qi::lit;
            using boost::spirit::qi::repeat;
            using boost::spirit::qi::_1;
            using boost::spirit::qi::_a;
            using boost::spirit::qi::_val;
            using boost::phoenix::at_c;
            using boost::phoenix::static_cast_;

            ipv6address
                =                                                                                                                                               repeat(6)[h16[_val[_a++]    = _1] >> ':'] >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>()        ]                                                                            >> lit("::")[_a = 1] >> repeat(5)[h16[_val[_a++]    = _1] >> ':'] >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>()        ] >> -(                                             h16[at_c<0>(_val) = _1]) >> lit("::")[_a = 2] >> repeat(4)[h16[_val[_a++]    = _1] >> ':'] >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>(), _a = 0] >> -(repeat(0, 1)[h16[_val[_a++] = _1] >> ':'] >> h16[_val[_a]      = _1]) >> lit("::")[_a = 3] >> repeat(3)[h16[_val[_a++]    = _1] >> ':'] >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>(), _a = 0] >> -(repeat(0, 2)[h16[_val[_a++] = _1] >> ':'] >> h16[_val[_a]      = _1]) >> lit("::")[_a = 4] >> repeat(2)[h16[_val[_a++]    = _1] >> ':'] >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>(), _a = 0] >> -(repeat(0, 3)[h16[_val[_a++] = _1] >> ':'] >> h16[_val[_a]      = _1]) >>     "::"          >>           h16[at_c<5>(_val) = _1] >> ':'  >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>(), _a = 0] >> -(repeat(0, 4)[h16[_val[_a++] = _1] >> ':'] >> h16[_val[_a]      = _1]) >>     "::"                                                       >> ls32[at_c<6>(_val) = at_c<0>(_1), at_c<7>(_val) = at_c<1>(_1)]
                |   eps[_val = array<uint16_t, 8>(), _a = 0] >> -(repeat(0, 5)[h16[_val[_a++] = _1] >> ':'] >> h16[_val[_a]      = _1]) >>     "::"          >>           h16[at_c<7>(_val) = _1]
                |   eps[_val = array<uint16_t, 8>(), _a = 0] >> -(repeat(0, 6)[h16[_val[_a++] = _1] >> ':'] >> h16[_val[_a]      = _1]) >>     "::"
                ;

            ls32
                =   h16 >> ':' >> h16
                |   ipv4address[at_c<0>(_val) = (_1 >> 16),
                                at_c<1>(_val) = (0x0000ffff & _1)]
                ;

            BOOST_SPIRIT_DEBUG_NODES((ipv6address))
        }

        boost::spirit::qi::rule<Iterator,
                                std::pair<std::uint64_t, std::uint64_t>()>
            start;
        boost::spirit::qi::rule<Iterator,
                                boost::spirit::qi::locals<unsigned>,
                                boost::array<std::uint16_t, 8>()>
            ipv6address;
        boost::spirit::qi::rule<Iterator, std::pair<std::uint16_t, std::uint16_t>()> ls32;
        boost::spirit::qi::uint_parser<std::uint16_t, 16, 1, 4> h16;
        ipv4_grammar<Iterator> ipv4address;
    };

    template <typename Iterator>
    struct components {
        boost::iterator_range<Iterator> scheme, userinfo, host, port, path, query, fragment;
    };


    template <typename Iterator>
    struct sub_delims_grammar :
        boost::spirit::qi::grammar<Iterator, char()> {

        sub_delims_grammar(): sub_delims_grammar::base_type(sub_delims)
        {
            using namespace boost::spirit::qi;
            sub_delims
               %=   char_("!$&\\()*+,;=")
                ;
        }

        boost::spirit::qi::rule<Iterator, char()> sub_delims;
    };


    template <typename Iterator>
    struct pct_encoded_grammar :
        boost::spirit::qi::grammar<Iterator, std::string()> {

        pct_encoded_grammar(): pct_encoded_grammar::base_type(pct_encoded)
        {
            using namespace boost::spirit::qi;
            pct_encoded
               %=   '%' >> xdigit >> xdigit
                ;
        }

        boost::spirit::qi::rule<Iterator, std::string()> pct_encoded;
    };


    template <typename Iterator>
    struct unreserved_grammar :
        boost::spirit::qi::grammar<Iterator, char()> {

        unreserved_grammar(): unreserved_grammar::base_type(unreserved)
        {
            using namespace boost::spirit::qi;

            unreserved
               %=   alnum
                |   char_("-._~")
                ;
        }

        boost::spirit::qi::rule<Iterator, char()> unreserved;
    };


    template <typename Iterator>
    struct pchar_grammar : boost::spirit::qi::grammar<Iterator> {
        pchar_grammar(): pchar_grammar::base_type(pchar)
        {
            using namespace boost::spirit::qi;

            pchar
                =   unreserved
                |   pct_encoded
                |   sub_delims
                |   char_(":@")
                ;
        }

        boost::spirit::qi::rule<Iterator> pchar;
        sub_delims_grammar<Iterator> sub_delims;
        pct_encoded_grammar<Iterator> pct_encoded;
        unreserved_grammar<Iterator> unreserved;
    };


    template <typename Iterator>
    struct scheme_grammar : boost::spirit::qi::grammar<Iterator> {
        scheme_grammar(): scheme_grammar::base_type(scheme)
        {
            using namespace boost::spirit::qi;
            scheme
                =   alpha >> *(alnum | char_("+-."))
                ;
        }

        boost::spirit::qi::rule<Iterator> scheme;
    };


    template <typename Iterator>
    struct authority_grammar : boost::spirit::qi::grammar<Iterator> {
        explicit authority_grammar(components<Iterator> & c):
            authority_grammar::base_type(authority),
            components_(c)
        {
            using namespace boost::spirit::qi;

            userinfo
                =  *(   unreserved
                    |   pct_encoded
                    |   sub_delims
                    |   ':'
                    )
                ;

            ip_literal
                =   '[' >> (ipv6address | ipvfuture) >> ']'
                ;

            ipvfuture
                =   'v' >> +xdigit >> '.' >> +(unreserved | sub_delims | ':')
                ;

            ipv6address
                =                                                 repeat(6)[h16 >> ':'] >> ls32
                |                                         "::" >> repeat(5)[h16 >> ':'] >> ls32
                |   -(                            h16) >> "::" >> repeat(4)[h16 >> ':'] >> ls32
                |   -(repeat(0, 1)[h16 >> ':'] >> h16) >> "::" >> repeat(3)[h16 >> ':'] >> ls32
                |   -(repeat(0, 2)[h16 >> ':'] >> h16) >> "::" >> repeat(2)[h16 >> ':'] >> ls32
                |   -(repeat(0, 3)[h16 >> ':'] >> h16) >> "::" >>           h16 >> ':'  >> ls32
                |   -(repeat(0, 4)[h16 >> ':'] >> h16) >> "::"                          >> ls32
                |   -(repeat(0, 5)[h16 >> ':'] >> h16) >> "::" >>           h16
                |   -(repeat(0, 6)[h16 >> ':'] >> h16) >> "::"
                ;

            h16
                =   repeat(1, 4)[xdigit]
                ;

            ls32
                =   h16 >> ':' >> h16
                |   ipv4address
                ;

            ipv4address
                =   dec_octet >> '.' >> dec_octet >> '.' >> dec_octet >> '.'
                    >> dec_octet
                ;

            dec_octet
                =   "25" >> char_("0-5")
                |   '2' >> char_("0-4") >> digit
                |   '1' >> repeat(2)[digit]
                |   char_("1-9") >> digit
                |   digit
                ;

            reg_name
                =  *(   unreserved
                    |   pct_encoded
                    |   sub_delims
                    )
                ;

            host
                =   ip_literal
                |   ipv4address
                |   reg_name
                ;

            port
                =   *digit
                ;

            authority
                =  -(   raw[userinfo][boost::phoenix::ref(userinfo_temp_) = _1]
                        >> '@'
                    )[
                        boost::phoenix::ref(components_.userinfo) =
                            boost::phoenix::ref(userinfo_temp_)
                    ]
                    >> raw[host][boost::phoenix::ref(components_.host) = _1]
                    >> -(':' >> raw[port][boost::phoenix::ref(components_.port) = _1])
                ;

            BOOST_SPIRIT_DEBUG_NODE(authority);
            BOOST_SPIRIT_DEBUG_NODE(host);
            BOOST_SPIRIT_DEBUG_NODE(ipv4address);
            BOOST_SPIRIT_DEBUG_NODE(ipv6address);
            BOOST_SPIRIT_DEBUG_NODE(dec_octet);
            BOOST_SPIRIT_DEBUG_NODE(reg_name);
            BOOST_SPIRIT_DEBUG_NODE(ipv6address);
            BOOST_SPIRIT_DEBUG_NODE(ls32);
            BOOST_SPIRIT_DEBUG_NODE(h16);
        }

        components<Iterator> & components_;
        boost::iterator_range<Iterator> userinfo_temp_;

        boost::spirit::qi::rule<Iterator> authority, ip_literal, ipv6address,
            userinfo, host, port, reg_name, ipv4address, dec_octet, h16, ls32,
            ipvfuture;
        sub_delims_grammar<Iterator> sub_delims;
        pct_encoded_grammar<Iterator> pct_encoded;
        unreserved_grammar<Iterator> unreserved;
    };


    template <typename Iterator>
    struct path_abempty_grammar : boost::spirit::qi::grammar<Iterator> {

        path_abempty_grammar(): path_abempty_grammar::base_type(path_abempty)
        {
            using namespace boost::spirit::qi;
            path_abempty
                =   *('/' >> *pchar)
                ;
        }

        boost::spirit::qi::rule<Iterator> path_abempty;
        pchar_grammar<Iterator> pchar;
    };


    template <typename Iterator>
    struct path_absolute_grammar : boost::spirit::qi::grammar<Iterator> {

        path_absolute_grammar(): path_absolute_grammar::base_type(path_absolute)
        {
            using namespace boost::spirit::qi;
            path_absolute
                =   '/' >> -(+pchar >> *('/' >> *pchar))
                ;
        }

        boost::spirit::qi::rule<Iterator> path_absolute;
        pchar_grammar<Iterator> pchar;
    };


    template <typename Iterator>
    struct hier_part_grammar : boost::spirit::qi::grammar<Iterator> {
        explicit hier_part_grammar(components<Iterator> & c):
            hier_part_grammar::base_type(hier_part),
            components_(c),
            authority(c)
        {
            using namespace boost::spirit::qi;

            path_rootless
                =   +pchar >> *('/' >> *pchar)
                ;

            path_empty
                =   eps
                ;

            hier_part
                =   "//" >> authority >> raw[path_abempty][
                        boost::phoenix::ref(components_.path) = _1
                    ]
                |   raw[(path_absolute | path_rootless | path_empty)][
                        boost::phoenix::ref(components_.path) = _1
                    ]
                ;
        }

        components<Iterator> & components_;

        boost::spirit::qi::rule<Iterator> hier_part, path_rootless, path_empty;
        authority_grammar<Iterator> authority;
        path_abempty_grammar<Iterator> path_abempty;
        path_absolute_grammar<Iterator> path_absolute;
        pchar_grammar<Iterator> pchar;
    };


    template <typename Iterator>
    struct query_grammar : boost::spirit::qi::grammar<Iterator> {
        query_grammar(): query_grammar::base_type(query)
        {
            using namespace boost::spirit::qi;
            query
                =  *(pchar | char_("/?"))
                ;
        }

        boost::spirit::qi::rule<Iterator> query;
        pchar_grammar<Iterator> pchar;
    };


    template <typename Iterator>
    struct fragment_grammar : boost::spirit::qi::grammar<Iterator> {

        fragment_grammar(): fragment_grammar::base_type(fragment)
        {
            using namespace boost::spirit::qi;
            fragment
                =  *(pchar | char_("/?"))
                ;
        }

        boost::spirit::qi::rule<Iterator> fragment;
        pchar_grammar<Iterator> pchar;
    };


    template <typename Iterator>
    struct relative_grammar : boost::spirit::qi::grammar<Iterator> {
        explicit relative_grammar(components<Iterator> & c):
            relative_grammar::base_type(relative_ref),
            components_(c),
            authority(c)
        {
            using namespace boost::spirit::qi;

            segment_nz_nc
                =  +(   unreserved 
                    |   pct_encoded
                    |   sub_delims
                    |   '@'
                    )
                ;

            path_noscheme
                =   segment_nz_nc >> *('/' >> *pchar)
                ;

            path_empty
                =   eps
                ;

            relative_part
                =   "//" >> authority >> raw[path_abempty][
                        boost::phoenix::ref(components_.path) = _1
                    ]
                |   raw[(path_absolute | path_noscheme | path_empty)][
                        boost::phoenix::ref(components_.path) = _1
                    ]
                ;

            relative_ref
                =   relative_part
                    >> -('?'
                    >> raw[query][boost::phoenix::ref(components_.query) = _1])
                    >> -('#'
                    >> raw[fragment][boost::phoenix::ref(components_.fragment) = _1])
                ;

            BOOST_SPIRIT_DEBUG_NODE(relative_ref);
            BOOST_SPIRIT_DEBUG_NODE(relative_part);
        }

        components<Iterator> & components_;

        boost::spirit::qi::rule<Iterator> relative_ref, relative_part,
            path_noscheme, path_empty, segment_nz_nc;
        sub_delims_grammar<Iterator> sub_delims;
        pct_encoded_grammar<Iterator> pct_encoded;
        unreserved_grammar<Iterator> unreserved;
        pchar_grammar<Iterator> pchar;
        authority_grammar<Iterator> authority;
        query_grammar<Iterator> query;
        fragment_grammar<Iterator> fragment;
        path_abempty_grammar<Iterator> path_abempty;
        path_absolute_grammar<Iterator> path_absolute;
    };


    template <typename Iterator>
    struct grammar : boost::spirit::qi::grammar<Iterator> {

        explicit grammar(components<Iterator> & c):
            grammar::base_type(uri_reference),
            components_(c),
            hier_part(c),
            relative_ref(c)
        {
            using namespace boost::spirit::qi;

            uri
                =   raw[scheme][boost::phoenix::ref(components_.scheme) = _1]
                    >> ':' >> hier_part
                    >> -('?' >> raw[query][boost::phoenix::ref(components_.query) = _1])
                    >> -('#' >> raw[fragment][boost::phoenix::ref(components_.fragment) = _1])
                ;

            uri_reference
                =   uri
                |   raw[eps][boost::phoenix::ref(components_.scheme) = _1] >> relative_ref
                ;

            BOOST_SPIRIT_DEBUG_NODE(uri_reference);
            BOOST_SPIRIT_DEBUG_NODE(uri);
            BOOST_SPIRIT_DEBUG_NODE(hier_part);
        }

        typedef boost::spirit::qi::rule<Iterator> rule_t;

        components<Iterator> & components_;

        rule_t uri_reference, uri;
        scheme_grammar<Iterator> scheme;
        hier_part_grammar<Iterator> hier_part;
        relative_grammar<Iterator> relative_ref;
        query_grammar<Iterator> query;
        fragment_grammar<Iterator> fragment;
    };


    template <typename Iterator>
    struct absolute_grammar : boost::spirit::qi::grammar<Iterator> {

        explicit absolute_grammar(components<Iterator> & c):
            absolute_grammar::base_type(absolute_uri),
            components_(c),
            hier_part(c)
        {
            using namespace boost::spirit::qi;
            absolute_uri
                =   raw[scheme][boost::phoenix::ref(components_.fragment) = _1]
                    >> ':' >> hier_part
                    >> -('?' >> raw[query][boost::phoenix::ref(components_.fragment) = _1])
                ;
        }

        components<Iterator> & components_;

        boost::spirit::qi::rule<Iterator> absolute_uri;
        scheme_grammar<Iterator> scheme;
        hier_part_grammar<Iterator> hier_part;
        query_grammar<Iterator> query;
    };
} // namespace uri

# endif // ifndef URI_GRAMMAR_HPP
