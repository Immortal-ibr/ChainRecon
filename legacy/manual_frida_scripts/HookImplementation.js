Java.perform(() => {
  const Activity = Java.use('com.thingclips.smart.mqtt.MqttAndroidClient');
  Activity.run.implementation = function () {
    MqttAndroidClient.getMqttToken(bundle);
    this.run();
  };
});
