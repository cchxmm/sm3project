import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'services/otp_store.dart';
import 'screens/home_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await OtpStore.instance.init();
  runApp(const OtpApp());
}

class OtpApp extends StatelessWidget {
  const OtpApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<OtpStore>.value(
      value: OtpStore.instance,
      child: MaterialApp(
        title: 'OTP Authenticator',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: Colors.blue,
            brightness: Brightness.light,
          ),
          useMaterial3: true,
          appBarTheme: const AppBarTheme(
            centerTitle: false,
            elevation: 1,
          ),
        ),
        darkTheme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: Colors.blue,
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
        ),
        home: const HomeScreen(),
      ),
    );
  }
}
