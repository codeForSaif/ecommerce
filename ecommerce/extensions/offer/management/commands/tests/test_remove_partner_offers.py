import ddt
from django.core.management import call_command
from django.core.management.base import CommandError
from mock import patch
from oscar.core.loading import get_model
from oscar.test import factories
from testfixtures import LogCapture

from ecommerce.tests.factories import PartnerFactory
from ecommerce.tests.testcases import TestCase

Catalog = get_model('catalogue', 'Catalog')
ConditionalOffer = get_model('offer', 'ConditionalOffer')
LOGGER_NAME = 'ecommerce.extensions.offer.management.commands.remove_partner_offers'
OrderLine = get_model('order', 'Line')


@ddt.ddt
class RemovePartnerOffersTests(TestCase):
    """Tests for remove_partner_offers management command."""

    PARTNER_CODE = 'testX'
    YES_NO_PATCH_LOCATION = 'ecommerce.extensions.offer.management.commands.remove_partner_offers.query_yes_no'

    def test_partner_required(self):
        """Test that command raises partner required error."""
        with self.assertRaisesRegexp(CommandError, 'Error: argument --partner is required'):
            call_command('remove_partner_offers')

    def test_no_offer_found(self):
        """Test that command logs no offer found."""
        with LogCapture(LOGGER_NAME) as log:
            call_command('remove_partner_offers', '--partner={}'.format(self.PARTNER_CODE))
            log.check(
                (
                    LOGGER_NAME,
                    'INFO',
                    'No offer found for partner {}.'.format(self.PARTNER_CODE)
                )
            )

    @ddt.data(True, False)
    def test_remove_partner_offers(self, yes_no_value):
        """Test that command removes partner offers."""
        partner = PartnerFactory(short_code=self.PARTNER_CODE)
        catalog = Catalog.objects.create(partner=partner)
        offer = factories.ConditionalOfferFactory()
        offer_range = offer.benefit.range
        offer_range.catalog = catalog
        offer_range.save()

        with patch(self.YES_NO_PATCH_LOCATION) as mocked_yes_no:
            mocked_yes_no.return_value = yes_no_value
            with LogCapture(LOGGER_NAME) as log:
                call_command('remove_partner_offers', '--partner={}'.format(self.PARTNER_CODE))
                if yes_no_value:
                    log_msg = '1 conditional offer removed successfully.'
                else:
                    log_msg = 'Operation canceled.'

                log.check((LOGGER_NAME, 'INFO', log_msg))
