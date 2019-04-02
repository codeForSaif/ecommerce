"""
Django rules for enterprise
"""
from __future__ import absolute_import

import rules
import waffle
from edx_rbac.utils import (
    get_decoded_jwt_from_request,
    get_request_or_stub,
    request_user_has_implicit_access_via_jwt,
    user_has_access_via_database
)

from ecommerce.core.constants import ENTERPRISE_COUPON_ADMIN_ROLE, SYSTEM_ENTERPRISE_OPERATOR_ROLE
from ecommerce.core.models import EcommerceFeatureRoleAssignment
from ecommerce.enterprise.constants import USE_ROLE_BASED_ACCESS_CONTROL


@rules.predicate
def request_user_is_edx_operator(user, context):    # pylint: disable=unused-argument
    """
    Check that if request user has `SYSTEM_ENTERPRISE_OPERATOR_ROLE` role.
     Returns:
        boolean: whether the request user has access or not.
    """
    request = get_request_or_stub()
    decoded_jwt = get_decoded_jwt_from_request(request)
    jwt_roles_claim = decoded_jwt.get('roles', [])
    for role_data in jwt_roles_claim:
        role_in_jwt, __, __ = role_data.partition(':')
        if role_in_jwt == SYSTEM_ENTERPRISE_OPERATOR_ROLE:
            return True
    return False


@rules.predicate
def request_user_has_implicit_access(user, context):  # pylint: disable=unused-argument
    """
    Check that if request user has implicit access to `ENTERPRISE_COUPON_ADMIN_ROLE` feature role.
     Returns:
        boolean: whether the request user has access or not
    """
    request = get_request_or_stub()
    decoded_jwt = get_decoded_jwt_from_request(request)
    if not context:
        return False
    return request_user_has_implicit_access_via_jwt(
        decoded_jwt, ENTERPRISE_COUPON_ADMIN_ROLE, context
    ) if decoded_jwt else False


@rules.predicate
def request_user_has_explicit_access(user, context):
    """
    Check that if request user has explicit access to `ENTERPRISE_COUPON_ADMIN_ROLE` feature role.
    Returns:
        boolean: whether the request user has access or not
    """
    if not context:
        return False
    return user_has_access_via_database(
        user,
        ENTERPRISE_COUPON_ADMIN_ROLE,
        EcommerceFeatureRoleAssignment,
        context=context
    )


@rules.predicate
def rbac_permissions_disabled(user, obj):  # pylint: disable=unused-argument
    """
    Temporary check for rbac based permissions being enabled.
    """
    return not waffle.switch_is_active(USE_ROLE_BASED_ACCESS_CONTROL)


rules.add_perm(
    'enterprise.can_view_coupon',
    rbac_permissions_disabled |
    request_user_is_edx_operator |
    request_user_has_implicit_access |
    request_user_has_explicit_access
)
rules.add_perm(
    'enterprise.can_assign_coupon',
    rbac_permissions_disabled |
    request_user_is_edx_operator |
    request_user_has_implicit_access |
    request_user_has_explicit_access
)
