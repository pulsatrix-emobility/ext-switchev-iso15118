from unittest.mock import AsyncMock, Mock, patch

import pytest

from iso15118.evcc.states.iso15118_2_states import (
    CurrentDemand,
    PaymentDetails,
    PaymentServiceSelection,
    PowerDelivery,
    ServiceDetail,
    ServiceDiscovery,
    WeldingDetection,
)
from iso15118.shared.messages.datatypes import SelectedService
from iso15118.shared.messages.enums import AuthEnum
from iso15118.shared.messages.iso15118_2.body import (
    Body,
    PaymentServiceSelectionRes,
    ServiceDetailRes,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    CertificateChain,
    ChargingSession,
    ParameterSet,
    ResponseCode,
    ServiceCategory,
    ServiceID,
    ServiceParameterList,
)
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
from iso15118.shared.notifications import StopNotification
from tests.iso15118_2.evcc.states.test_messages import (
    get_v2g_message_current_demand_res,
    get_v2g_message_current_demand_res_with_stop_charging,
    get_v2g_message_power_delivery_res,
)


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestEvScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self, comm_evcc_session_mock):
        self.comm_session = comm_evcc_session_mock

    async def test_current_demand_to_current_demand(self):
        #  according V2G2-531
        current_demand = CurrentDemand(self.comm_session)
        await current_demand.process_message(
            message=get_v2g_message_current_demand_res()
        )
        assert current_demand.next_state == CurrentDemand

    async def test_current_demand_power_delivery_when_notification_is_stop_charging(
        self,
    ):
        # according V2G2-679 (EVSENotification = EVSENotification)
        # as well in states chargeParameterDiscoveryRes, PowerDeliveryREs,
        # MeteringReceiptRes, PrechargeRes, currentDemandRes, WeldingDetectionREs ??
        current_demand = CurrentDemand(self.comm_session)
        await current_demand.process_message(
            message=get_v2g_message_current_demand_res_with_stop_charging(),
        )
        assert current_demand.next_state == PowerDelivery

    async def test_current_demand_to_power_delivery_when_stopped_by_ev(self):
        # V2G2-527
        pass

    async def test_power_delivery_to_welding_detection_when_charge_progress_is_stop(
        self,
    ):
        # V2G2-533
        self.comm_session.stop_reason = StopNotification(True, "pytest")
        power_delivery = PowerDelivery(self.comm_session)
        self.comm_session.charging_session_stop_v2 = ChargingSession.TERMINATE
        await power_delivery.process_message(
            message=get_v2g_message_power_delivery_res()
        )
        assert power_delivery.next_state == WeldingDetection

    @pytest.mark.parametrize(
        "offered_sets, install_needed, expected",
        [
            ([1, 2], True, [1]),
            (None, True, []),
            ([], True, []),
            ([2], True, []),
            ([99], True, []),
            ([1], False, []),
        ],
    )
    async def test_certificate_service_selection(
        self, offered_sets, install_needed, expected
    ):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        self.comm_session.is_tls = True
        self.comm_session.selected_services = []
        self.comm_session.service_details_to_request = []
        self.comm_session.ev_controller.is_cert_install_needed = AsyncMock(
            return_value=install_needed
        )
        discovery = ServiceDiscovery(self.comm_session)
        await discovery.select_services(
            Mock(
                charge_service=Mock(service_id=ServiceID.CHARGING),
                service_list=Mock(
                    services=[
                        Mock(
                            service_id=ServiceID.CERTIFICATE,
                            service_category=ServiceCategory.CERTIFICATE,
                        )
                    ]
                ),
            )
        )
        assert self.comm_session.selected_services == [
            SelectedService(service_id=ServiceID.CHARGING)
        ]
        assert self.comm_session.service_details_to_request == (
            [ServiceID.CERTIFICATE] if install_needed else []
        )
        self.comm_session.service_details_to_request = []
        detail = ServiceDetail(self.comm_session)
        await detail.process_message(
            V2GMessage(
                header=MessageHeader(session_id=self.comm_session.session_id),
                body=Body(
                    service_detail_res=ServiceDetailRes(
                        response_code=ResponseCode.OK,
                        service_id=ServiceID.CERTIFICATE,
                        service_parameter_list=(
                            None
                            if offered_sets is None
                            else ServiceParameterList(
                                parameter_set=[
                                    ParameterSet(parameter_set_id=value, parameters=[])
                                    for value in offered_sets
                                ]
                            )
                        ),
                    )
                ),
            )
        )
        assert detail.next_state == PaymentServiceSelection
        request = detail.message.body.payment_service_selection_req
        assert request.selected_service_list.selected_service == [
            SelectedService(service_id=ServiceID.CHARGING),
            *[
                SelectedService(
                    service_id=ServiceID.CERTIFICATE, parameter_set_id=value
                )
                for value in expected
            ],
        ]

    async def test_unselected_certificate_service_uses_payment_details(self):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        self.comm_session.selected_services = [SelectedService(service_id=1)]
        self.comm_session.ev_controller.is_cert_install_needed = AsyncMock(
            return_value=True
        )
        state = PaymentServiceSelection(self.comm_session)
        module = "iso15118.evcc.states.iso15118_2_states."
        with patch(module + "load_cert", return_value=b"synthetic"), patch(
            module + "get_cert_cn", return_value="DETEST00000000"
        ), patch(
            module + "load_cert_chain",
            return_value=CertificateChain(certificate=b"synthetic"),
        ):
            await state.process_message(
                V2GMessage(
                    header=MessageHeader(session_id=self.comm_session.session_id),
                    body=Body(
                        payment_service_selection_res=PaymentServiceSelectionRes(
                            response_code=ResponseCode.OK
                        )
                    ),
                )
            )
        assert state.next_state == PaymentDetails
        assert state.message.body.payment_details_req is not None
