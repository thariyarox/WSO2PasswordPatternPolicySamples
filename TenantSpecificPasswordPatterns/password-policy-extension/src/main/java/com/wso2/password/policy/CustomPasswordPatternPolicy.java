package com.wso2.password.policy;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Custom password policy extension
 */

public class CustomPasswordPatternPolicy extends AbstractPasswordPolicyEnforcer {

    private static final Log log = LogFactory.getLog(CustomPasswordPatternPolicy.class);
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private Map<String, String> tenantPasswordPolicyPatterns;
    private String defaultPasswordPolicyPattern = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";


    /**
     * Validates the password against the pattern provided
     *
     * @param args - comes as object array, contains the username and the password.
     * @return boolean
     */
    public boolean enforce(Object... args) {

        boolean status = true;

        if (args != null) {

            String password = args[0].toString();
            String userName = args[1].toString();

            log.info("Updating password for user : " + userName);
            log.info("password : " + password);

            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

            Matcher matcher = getPasswordPattern(tenantDomain).matcher(password);

            if (matcher.matches()) {

                log.info("password : " + password + " matches with the pattern" + matcher.pattern().toString());

                status = true;
            } else {
                log.info("password : " + password + " did not match the patten " +  matcher.pattern().toString());

                errorMessage = "Password does not match the pattern " +  matcher.pattern().toString();
                status = false;
            }

        }

        return status;
    }

    /**
     * Load the extension while startup
     *
     * @param parameters contains values related to this extension define in the identity-mgt.properties
     */
    public void init(Map<String, String> parameters) {

        if (parameters != null && parameters.size() > 0) {
            // Parameters related to this extension defined in identity-mgt.properties file
            if (StringUtils.isNotEmpty(parameters.get("pattern"))) {
                defaultPasswordPolicyPattern = parameters.get("pattern");
            }
        }

        // Add sample policy patterns
        tenantPasswordPolicyPatterns = new HashMap<String, String>();
        tenantPasswordPolicyPatterns.put(SUPER_TENANT_DOMAIN, defaultPasswordPolicyPattern);
        tenantPasswordPolicyPatterns.put("wso2.com", "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{10,}$");
        tenantPasswordPolicyPatterns.put("abc.com", "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[#$%^&+=])(?=\\S+$).{8,}$");
    }


    /**
     * Get the password policy pattern associated with a particular tenant.
     * @param tenantDomain
     * @return Pattern related to the tenant
     */
    private Pattern getPasswordPattern(String tenantDomain) {

        String pattern = tenantPasswordPolicyPatterns.get(tenantDomain);

        if (StringUtils.isEmpty(pattern)) {
            // If tenant has no password policy pattern defined, take super tenant's pattern
            pattern = tenantPasswordPolicyPatterns.get(SUPER_TENANT_DOMAIN);

        }

        return Pattern.compile(pattern);

    }

}
