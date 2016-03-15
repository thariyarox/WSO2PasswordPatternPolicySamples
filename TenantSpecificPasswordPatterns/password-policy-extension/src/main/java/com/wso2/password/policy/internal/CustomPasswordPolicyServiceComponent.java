package com.wso2.password.policy.internal;

import com.wso2.password.policy.CustomPasswordPatternDataHolder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="com.wso2.password.policy"
 * immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */

public class CustomPasswordPolicyServiceComponent {
    private static Log log = LogFactory.getLog(CustomPasswordPolicyServiceComponent.class);


    protected void activate(ComponentContext context) {

        log.info("Custom Password Policy bundle is activated");
    }


    protected void deactivate(ComponentContext context) {
        log.info("Custom Password Policy bundle is is de-activated");
    }


    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        CustomPasswordPatternDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        CustomPasswordPatternDataHolder.getInstance().setRealmService(null);
    }

}
