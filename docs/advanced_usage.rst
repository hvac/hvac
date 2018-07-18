Advanced Usage
==============

Custom Requests / HTTP Adapter
------------------------------

In hvac version 0.6.3, calls to the requests module (which provides the methods hvac utilizes to send HTTP/HTTPS request to Vault instances) were extracted from the :class:`Client <hvac.v1.Client>` class and moved to a newly added :meth:`hvac.adapters` module. The :class:`Client <hvac.v1.Client>` class itself defaults to an instance of the :class:`Request <hvac.adapters.Request>` class for its :attr:`_adapter <hvac.v1.Client._adapter>` private attribute attribute if no adapter argument is provided to its :meth:`constructor <hvac.v1.Client.__init__>`. This attribute provides an avenue for modifying the manner in which hvac completes request. To enable this type of customization, implement a class of type :meth:`hvac.adapters.Adapter`, override its abstract methods, and pass an instance of this custom class to the adapter argument of the :meth:`Client constructor <hvac.v1.Client.__init__>`
