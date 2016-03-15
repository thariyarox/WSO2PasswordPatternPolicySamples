package com.wso2.password.policy;

import org.wso2.carbon.user.core.service.RealmService;

public class CustomPasswordPatternDataHolder {

    private static RealmService realmService;
    private static CustomPasswordPatternDataHolder customPasswordPatternDataHolder;

    /**
     * Constructor is made private for singleton pattern
     */
    private CustomPasswordPatternDataHolder() {

    }

    /**
     * Singleton instance
     *
     * @return CustomPasswordPatternDataHolder
     */
    public static CustomPasswordPatternDataHolder getInstance() {

        if (customPasswordPatternDataHolder == null) {
            synchronized (customPasswordPatternDataHolder) {
                if (customPasswordPatternDataHolder == null) {
                    customPasswordPatternDataHolder = new CustomPasswordPatternDataHolder();
                }
            }
        }

        return customPasswordPatternDataHolder;
    }

    /**
     * Get the realm service
     *
     * @return
     */
    public RealmService getRealmService() {
        return realmService;
    }

    /**
     * Set realm service
     *
     * @param realmService
     */
    public void setRealmService(RealmService realmService) {

        CustomPasswordPatternDataHolder.realmService = realmService;
    }

}
