package org.jasig.cas.authentication.saml

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver
import org.jasig.cas.authentication.principal.Credentials
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver
import org.jasig.cas.authentication.principal.Principal
import org.jasig.cas.authentication.principal.SimplePrincipal
import org.jasig.cas.service.IdpService
import org.jasig.services.persondir.IPersonAttributeDao
import org.jasig.services.persondir.IPersonAttributes
import org.jasig.services.persondir.support.StubPersonAttributeDao
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired

import javax.validation.constraints.NotNull

/**
 * {@link org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver} for {@link SpringSecuritySamlCredentials}
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
class SpringSecuritySamlCredentialsToPrincipalResolver implements CredentialsToPrincipalResolver {
    @Autowired
    IdpService idpService


    /** Log instance. */
    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    private boolean returnNullIfNoAttributes = false;

    /** Repository of principal attributes to be retrieved */
    @NotNull
    private IPersonAttributeDao attributeRepository = new StubPersonAttributeDao(new HashMap<String, List<Object>>());

    @Override
    public Principal resolvePrincipal(Credentials credentials) {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to resolve a principal...");
        }

        final String principalId2 = idpService.extractPrincipalId(credentials);

        if (log.isDebugEnabled()) {
            log.debug("Received PrimaryPrincipal (NameID and provider) [" + principalId2 + "]");
        }

        final IPersonAttributes personAttributes = this.attributeRepository.getPerson(principalId2);

        if(personAttributes == null){
//            Return null and error to the need to associate account page
            return null;
        }

        final String principalId = (String) personAttributes.getAttributeValue("netId");

        if (log.isDebugEnabled()) {
            log.debug("Creating SimplePrincipal for [" + principalId + "]");
        }

        final Map<String, List<Object>> attributes;

        if (personAttributes == null) {
            attributes = null;
        } else {
            attributes = personAttributes.getAttributes();
        }

        if (attributes == null & !this.returnNullIfNoAttributes) {
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

    public final void setAttributeRepository(final IPersonAttributeDao attributeRepository) {
        this.attributeRepository = attributeRepository;
    }

    public void setReturnNullIfNoAttributes(final boolean returnNullIfNoAttributes) {
        this.returnNullIfNoAttributes = returnNullIfNoAttributes;
    }

    @Override
    boolean supports(Credentials credentials) {
        return credentials == null ? false : SpringSecuritySamlCredentials.isAssignableFrom(credentials.class);
    }


}
