from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from govstack_api.building_blocks.bb_digital_registries.controllers.single_record_controllers import \
    create_or_update_record_controller
from govstack_api.building_blocks.bb_digital_registries.serializers import CombinedValidatorSerializer
from govstack_api.building_blocks.bb_digital_registries.swagger_schema import request_body_schema, \
    create_or_update_response


class UpdateOrCreateRecordView(APIView):
    @swagger_auto_schema(
        operation_description='''API updates existing record if matching with input parameters is
            successful. If record is not found the API will create a new record.''',
        request_body=request_body_schema,
        responses=create_or_update_response
    )
    def post(self, request, registryname, versionnumber):
        serializer = CombinedValidatorSerializer(data=request.data)
        if serializer.is_valid():
            status_code, registry_record = create_or_update_record_controller(
                request, serializer.data, registryname, versionnumber
            )
            if status_code == 200:
                return Response(registry_record, status=status.HTTP_200_OK)
            else:
                return Response(serializer.data, status=status_code)
        return Response(status=status.HTTP_400_BAD_REQUEST)
