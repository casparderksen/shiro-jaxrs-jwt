package org.apache.shiro.authz.provider;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.realm.text.TextConfigurationRealm;
import org.apache.shiro.util.CollectionUtils;

import java.text.ParseException;
import java.util.Collection;

@Slf4j
public class IniPermissionProvider extends TextConfigurationRealm implements PermissionProvider {

    @Setter
    private String resourcePath = "classpath:roles.ini";

    @Override
    public Collection<Permission> getPermissions(String role) {
        return getRole(role).getPermissions();
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

    @Override
    protected void processDefinitions() {
        try {
            processRoleDefinitions();
        } catch (ParseException e) {
            String msg = "Unable to parse role definitions.";
            throw new ConfigurationException(msg, e);
        }
    }
}
