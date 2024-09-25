from rest_framework import serializers
from .models import Target, PortList, ScanConfig,Task, Crawler,TelegramUser,TargetSchedule,ScanHistory

from rest_framework import serializers
from .models import Vulnerability, SecurityAlert,Correlation

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__' 

class SecurityAlertSerializer(serializers.ModelSerializer):
    vulnerability = VulnerabilitySerializer(read_only=True) 

    class Meta:
        model = SecurityAlert
        fields = '__all__'  

class TargetSerializer(serializers.ModelSerializer):
    port_list = serializers.ChoiceField(choices=PortList.choices)

    class Meta:
        model = Target
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    scan_config = serializers.ChoiceField(choices=ScanConfig.choices)
    target = TargetSerializer()
    class Meta:
        model = Task
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    scan_config = serializers.ChoiceField(choices=ScanConfig.choices)
    target = serializers.PrimaryKeyRelatedField(queryset=Target.objects.all())

    class Meta:
        model = Task
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['target'] = TargetSerializer(instance.target).data
        return representation


class CorrelationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Correlation
        fields = '__all__'

class CrawlerSerializer(serializers.ModelSerializer):
    correlations = CorrelationSerializer(many=True, read_only=True)
    class Meta:
        model = Crawler
        fields = '__all__'
        
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['target'] = TargetSerializer(instance.target).data
        return representation

class TelegramUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = TelegramUser
        fields = '__all__'

class TargetScheduleSerializer(serializers.ModelSerializer):
    target = TargetSerializer()
    class Meta:
        model = TargetSchedule
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['target'] = TargetSerializer(instance.target).data
        return representation
    
class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['task'] = TaskSerializer(instance.task).data
        return representation