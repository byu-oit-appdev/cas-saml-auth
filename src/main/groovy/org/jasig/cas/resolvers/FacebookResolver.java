package org.jasig.cas.resolvers;

/**
 * Created by swlyons on 7/29/2016.
 */
import org.jasig.cas.credentials.FacebookCredentials;
import org.apache.log4j.Logger;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.services.persondir.IPersonAttributeDao;
import org.jasig.services.persondir.IPersonAttributes;
import org.springframework.beans.factory.InitializingBean;

import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FacebookResolver implements CredentialsToPrincipalResolver, InitializingBean {

    private static final Logger LOG = Logger.getLogger(FacebookResolver.class);

    /** Repository of principal attributes to be retrieved */
    @NotNull
    private IPersonAttributeDao attributeRepository;

    @Override
    public Principal resolvePrincipal(Credentials credentials) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Attempting to resolve a principal...");
        }

        final FacebookCredentials facebookCredentials = (FacebookCredentials) credentials;

        final String principalId2 = facebookCredentials.getUserID()+"#FACEBOOK_ID";

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received PrimaryPrincipal (NameID and provider) [" + principalId2 + "]");
        }

        final IPersonAttributes personAttributes = this.attributeRepository.getPerson(principalId2);

        if(personAttributes == null){
//            Return null and error to the need to associate account page
            return null;
        }

        final String principalId = (String) personAttributes.getAttributeValue("netId");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating SimplePrincipal for [" + principalId + "]");
        }

        final Map<String, List<Object>> attributes;

        if (personAttributes == null) {
            attributes = null;
        } else {
            attributes = personAttributes.getAttributes();
        }

        if (attributes == null) {
            return new SimplePrincipal(principalId);
        }

        if (attributes == null) {
            return null;
        }

        final Map<String, Object> convertedAttributes = new HashMap<String, Object>();

        for (final Map.Entry<String, List<Object>> entry : attributes.entrySet()) {
            final String key = entry.getKey();
            final Object value = entry.getValue().size() == 1 ? entry.getValue().get(0) : entry.getValue();
            convertedAttributes.put(key, value);
        }
        return new SimplePrincipal(principalId, convertedAttributes);
    }

    @Override
    public boolean supports(Credentials credentials) {
        return credentials == null ? false : (credentials instanceof FacebookCredentials);
    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }

    public final void setAttributeRepository(IPersonAttributeDao attributeRepository) {
        this.attributeRepository = attributeRepository;
    }
}
