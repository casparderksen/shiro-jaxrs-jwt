package org.apache.shiro.authz.policy.text;

import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IniPolicyProvider extends TextPolicyProvider {

    private static final Logger log = LoggerFactory.getLogger(IniPolicyProvider.class);

    private String resourcePath = "classpath:roles.ini";

    public void setResourcePath(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    @Override
    protected void onInit() {
        super.onInit();
        Ini ini = Ini.fromResourcePath(resourcePath);
        if (CollectionUtils.isEmpty(ini)) {
            throw new IllegalStateException("Cannot load Ini from resourcePath " + resourcePath);
        }
        processDefinitions(ini);
    }

    private void processDefinitions(Ini ini) {
        Ini.Section rolesSection = ini.getSection(IniRealm.ROLES_SECTION_NAME);
        if (CollectionUtils.isEmpty(rolesSection)) {
            log.warn("No [{}] section defined, cannot assign permissions", IniRealm.ROLES_SECTION_NAME);
        } else {
            log.debug("Processing the [{}] section", IniRealm.ROLES_SECTION_NAME);
            processRoleDefinitions(rolesSection);
        }
    }
}
