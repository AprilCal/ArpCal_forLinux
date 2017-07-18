#include <regex>
#include <iostream>
#include <stdio.h>
#include <string>
#include "parse-options.h"
using namespace std;




/*used to check the validity of ip address.
any dotted decimal notation ip address will
lead to a true return value.*/
bool is_IPAddress_valid(const string& ipaddress)
{
    /*do not check valdity in the regular expression, just perform some simple match.
      all 3 figures devided by dot can be valid, check them in the following lines.
      should better not pound a pile of shit regular expression.*/
    //const std::regex pattern("(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)");
    const std::regex pattern("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    match_results<std::string::const_iterator> result;
    bool valid = std::regex_match(ipaddress, result, pattern);
    if(valid&&(result.length()>0))
    {
	/*result[0] is regular expression match
	not a sub-expression match. we only check
	the valdity of sub-expression.         */
	for(int i=1;i<result.length();i++)
	{
	    string resultStr=result[i];
	    //cout<<atoi(resultStr.c_str())<<endl;
	    /*check if there are any 8bit lower than 0 or higher than 255*/
	    if(atoi(resultStr.c_str())<0||atoi(resultStr.c_str())>255)
		return 0;
	}
    }
    return valid;
}
