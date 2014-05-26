/*
Copyright (c) 2012-2014 Damian Kaczmarek <damian@codecharm.co.uk>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include <nan.h>
#include <unistd.h>
#include <uv.h>
#include <string>
#include <cstring>
#include <stdlib.h>

#include <security/pam_appl.h>

using namespace v8;

struct auth_context {
	auth_context() {
		remoteHost[0] = '\0';
		serviceName[0] = '\0';
		username[0] = '\0';
		password[0] = '\0';
	}
	Persistent<Function> callback;
	char serviceName[128];
	char username[128];
	char password[128];
	char remoteHost[128];
	int error;
	std::string errorString;
};

static int function_conversation(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
	struct pam_response* reply = (struct pam_response*)appdata_ptr;
	*resp = reply;
	return PAM_SUCCESS;
}


#define HANDLE_PAM_ERROR(header) if(retval != PAM_SUCCESS) { \
		data->errorString = header[0]?(std::string(header) + std::string(": ")):std::string("") + std::string(pam_strerror(local_auth_handle, retval)); \
		data->error = retval; \
		pam_end(local_auth_handle, retval); \
		return; \
}


// actual authentication function
void doing_auth_thread(uv_work_t* req) {
	auth_context* data = static_cast<auth_context*>(req->data);

	struct pam_response* reply = (struct pam_response*)malloc(sizeof(struct pam_response));
	reply->resp = strdup(data->password);
	reply->resp_retcode = 0;
	const struct pam_conv local_conversation = { function_conversation, (void*)reply };
	pam_handle_t* local_auth_handle = NULL; // this gets set by pam_start

	int retval = pam_start(strlen(data->serviceName)?data->serviceName:"login",
												 data->username, &local_conversation, &local_auth_handle);
	HANDLE_PAM_ERROR("pam_start")

	if(strlen(data->remoteHost)) {
		retval = pam_set_item(local_auth_handle, PAM_RHOST, data->remoteHost);
		HANDLE_PAM_ERROR("pam_set_item")
	}
	retval = pam_authenticate(local_auth_handle, 0);
	HANDLE_PAM_ERROR("")

	retval = pam_end(local_auth_handle, retval);
	if(retval != PAM_SUCCESS) {
		data->errorString = "pam_end: " + std::string(pam_strerror(local_auth_handle, retval));
		data->error = retval;
		return;
	}
	data->error = 0;
	return;
}

void after_doing_auth(uv_work_t* req, int status) {
	NanScope();

	auth_context* m = static_cast<auth_context*>(req->data);
	TryCatch try_catch;

	Handle<Value> args[1] = {NanUndefined()};
	if(m->error) {
		args[0] = NanNew<String>(m->errorString.c_str());
	}

  NanMakeCallback(NanGetCurrentContext()->Global(), NanNew(m->callback), 1, args);

	NanDisposePersistent(m->callback);

	delete m;
	delete req;

	if(try_catch.HasCaught())
		node::FatalException(try_catch);
}

NAN_METHOD(Authenticate) {
	NanScope();

	if(args.Length() < 3) {
		NanTypeError("Wrong number of arguments");
		NanReturnUndefined();
	}

	Local<Value> usernameVal(args[0]);
	Local<Value> passwordVal(args[1]);
	if(!usernameVal->IsString() || !passwordVal->IsString()) {
		NanTypeError("Argument 0 and 1 should be a String");
		NanReturnUndefined();
	}
	Local<Value> callbackVal(args[2]);
	if(!callbackVal->IsFunction()) {
		NanTypeError("Argument 2 should be a Function");
		NanReturnUndefined();
	}

	Local<Function> callback = Local<Function>::Cast(callbackVal);

	Local<String> username = Local<String>::Cast(usernameVal);
	Local<String> password = Local<String>::Cast(passwordVal);


	uv_work_t* req = new uv_work_t;
	struct auth_context* m = new auth_context;

	if(args.Length() == 4 && !args[3]->IsUndefined()) {
		Local<Array> options = Local<Array>::Cast(args[3]);
		Local<Value> res = options->Get(NanNew<String>("serviceName"));
		if(! res->IsUndefined()) {
			Local<String> serviceName = Local<String>::Cast(res);
			serviceName->WriteUtf8(m->serviceName, sizeof(m->serviceName) - 1);
		}
		res = options->Get(NanNew<String>("remoteHost"));
		if(! res->IsUndefined()) {
			Local<String> remoteHost = Local<String>::Cast(res);
			remoteHost->WriteUtf8(m->remoteHost, sizeof(m->remoteHost) - 1);
		}
	}
	NanAssignPersistent(m->callback, callback);

	username->WriteUtf8(m->username, sizeof(m->username) - 1);
	password->WriteUtf8(m->password, sizeof(m->password) - 1);

	req->data = m;

	uv_queue_work(uv_default_loop(), req, doing_auth_thread, after_doing_auth);

	NanReturnUndefined();
}

void init(Handle<Object> exports) {
	Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(Authenticate);
	exports->Set(NanNew<String>("authenticate"), tpl->GetFunction());
}

NODE_MODULE(authenticate_pam, init);
